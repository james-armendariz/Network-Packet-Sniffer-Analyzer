/*
 * parser_c.c — C extension replicating parser.py's parse_packet().
 *
 * WHY THIS EXISTS
 * ---------------
 * parse_packet() runs on every single packet that crosses the wire.
 * In Python it pays three costs that C avoids:
 *
 *   1. struct.unpack() allocates a new tuple on every call, then we
 *      immediately destructure and discard it.
 *   2. Every field assignment on a Python dataclass goes through the
 *      interpreter's attribute machinery (__setattr__, descriptor
 *      protocol, dict lookup).
 *   3. The Python bytecode interpreter itself has overhead per opcode
 *      that C simply does not have.
 *
 * The C extension eliminates all three: we read bytes directly out of
 * the buffer with pointer arithmetic and big-endian macros, allocate
 * Python objects once per packet, and set attributes with direct C API
 * calls (PyObject_SetAttrString) that bypass the interpreter loop.
 *
 * HOW PYTHON C EXTENSIONS WORK (the mental model)
 * ------------------------------------------------
 * Python's runtime is itself written in C. Every Python object —
 * integers, strings, lists, instances — is a C struct (PyObject *)
 * under the hood. The C API gives us functions to create and manipulate
 * those structs directly, without going through the interpreter.
 *
 * This file compiles into a shared library (parser_c.cpython-312-x86_64.so)
 * that Python's import system loads like any .py file. The module
 * registration at the bottom (PyModuleDef + PyMODINIT_FUNC) is the
 * C equivalent of a module's top-level namespace.
 *
 * INTERFACE CONTRACT
 * ------------------
 * parse_packet(data: bytes, timestamp: float) -> PacketInfo | None
 *
 * Identical signature to parser.py:parse_packet(). pipeline.py calls
 * this function without knowing or caring whether it's Python or C.
 * The returned object IS a parser.PacketInfo dataclass instance —
 * we import the Python dataclass classes at module init time and
 * instantiate them from C, so the rest of the system sees no difference.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------
 * Big-endian byte extraction macros.
 *
 * Network protocols are big-endian (most significant byte first).
 * x86 is little-endian. Rather than calling htons/htonl (which work
 * on native-endian values), we read raw bytes and shift them into
 * position manually. This is safe on any architecture and avoids
 * alignment requirements that would matter on strict-alignment CPUs.
 *
 * BE16(buf, offset): read 2 bytes at buf+offset as big-endian uint16
 * BE32(buf, offset): read 4 bytes at buf+offset as big-endian uint32
 * ------------------------------------------------------------------ */
#define BE16(buf, off) \
    (((unsigned char)(buf)[(off)] << 8) | (unsigned char)(buf)[(off)+1])

#define BE32(buf, off) \
    (((unsigned long)(unsigned char)(buf)[(off)+0] << 24) | \
     ((unsigned long)(unsigned char)(buf)[(off)+1] << 16) | \
     ((unsigned long)(unsigned char)(buf)[(off)+2] <<  8) | \
      (unsigned long)(unsigned char)(buf)[(off)+3])

/* Protocol constants — same values as parser.py */
#define ETH_TYPE_IPV4  0x0800
#define IP_PROTO_TCP   6
#define IP_PROTO_UDP   17
#define ETH_HEADER_LEN 14
#define MIN_IP_LEN     20
#define MIN_TCP_LEN    20
#define MIN_UDP_LEN    8

/* ------------------------------------------------------------------
 * Module-level references to Python dataclass types.
 * Populated once in PyMODINIT_FUNC, reused on every parse_packet call.
 * Storing them here avoids re-importing parser.py on every call.
 * ------------------------------------------------------------------ */
static PyObject *PacketInfo_cls   = NULL;
static PyObject *EthernetHeader_cls = NULL;
static PyObject *IPHeader_cls     = NULL;
static PyObject *TCPHeader_cls    = NULL;
static PyObject *UDPHeader_cls    = NULL;

/* ------------------------------------------------------------------
 * format_mac: convert 6 raw bytes into "aa:bb:cc:dd:ee:ff" string.
 * ------------------------------------------------------------------ */
static PyObject *
format_mac(const unsigned char *raw)
{
    char buf[18];
    snprintf(buf, sizeof(buf),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]);
    return PyUnicode_FromString(buf);
}

/* ------------------------------------------------------------------
 * format_ip: convert 4 raw bytes into "a.b.c.d" dotted-decimal string.
 * ------------------------------------------------------------------ */
static PyObject *
format_ip(const unsigned char *raw)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             raw[0], raw[1], raw[2], raw[3]);
    return PyUnicode_FromString(buf);
}

/* ------------------------------------------------------------------
 * build_ethernet: decode bytes [0:14] into an EthernetHeader instance.
 *
 * Frame layout:
 *   [0:6]   dst MAC
 *   [6:12]  src MAC
 *   [12:14] EtherType (big-endian uint16)
 * ------------------------------------------------------------------ */
static PyObject *
build_ethernet(const unsigned char *buf)
{
    PyObject *dst_mac = format_mac(buf);
    PyObject *src_mac = format_mac(buf + 6);
    PyObject *ethertype = PyLong_FromLong(BE16(buf, 12));

    PyObject *eth = PyObject_CallFunction(
        EthernetHeader_cls, "OOO", dst_mac, src_mac, ethertype
    );

    Py_DECREF(dst_mac);
    Py_DECREF(src_mac);
    Py_DECREF(ethertype);

    return eth;
}

/* ------------------------------------------------------------------
 * build_ipv4: decode the IPv4 header starting at buf+14.
 *
 * Byte 14: version (high nibble) | IHL (low nibble)
 *   version  = byte >> 4
 *   IHL      = (byte & 0x0F) * 4   <- header length in bytes
 *
 * We return the decoded IPHeader AND write ip_header_len back to the
 * caller so the TCP/UDP parser knows where the transport header starts.
 * ------------------------------------------------------------------ */
static PyObject *
build_ipv4(const unsigned char *buf, int *ip_header_len_out)
{
    unsigned char ver_ihl  = buf[14];
    int version            = ver_ihl >> 4;
    int ihl_bytes          = (ver_ihl & 0x0F) * 4;
    *ip_header_len_out     = ihl_bytes;

    unsigned int total_len = BE16(buf, 16);
    unsigned char ttl      = buf[22];
    unsigned char protocol = buf[23];
    PyObject *src_ip = format_ip(buf + 26);
    PyObject *dst_ip = format_ip(buf + 30);

    PyObject *ip = PyObject_CallFunction(
        IPHeader_cls, "iiiiiOO",
        version, ihl_bytes, (int)total_len, (int)ttl, (int)protocol,
        src_ip, dst_ip
    );

    Py_DECREF(src_ip);
    Py_DECREF(dst_ip);
    return ip;
}

/* ------------------------------------------------------------------
 * build_tcp: decode the TCP header starting at buf+transport_offset.
 *
 * TCP header layout (bytes relative to transport_offset):
 *   [0:2]   src port
 *   [2:4]   dst port
 *   [4:8]   sequence number
 *   [8:12]  acknowledgement number
 *   [12]    data offset (high nibble, in 32-bit words) | reserved
 *   [13]    flags byte (FIN SYN RST PSH ACK URG ECE CWR)
 *   [14:16] window size
 * ------------------------------------------------------------------ */
static PyObject *
build_tcp(const unsigned char *buf, int transport_offset)
{
    const unsigned char *t = buf + transport_offset;

    unsigned int src_port   = BE16(t, 0);
    unsigned int dst_port   = BE16(t, 2);
    unsigned long seq       = BE32(t, 4);
    unsigned long ack       = BE32(t, 8);
    int data_offset         = ((t[12] >> 4) & 0x0F) * 4;
    unsigned char flags     = t[13];
    unsigned int window     = BE16(t, 14);

    return PyObject_CallFunction(
        TCPHeader_cls, "IIIIiIi",
        src_port, dst_port,
        (unsigned int)seq, (unsigned int)ack,
        data_offset, (unsigned int)flags, window
    );
}

/* ------------------------------------------------------------------
 * build_udp: decode the UDP header (always exactly 8 bytes).
 *
 *   [0:2] src port
 *   [2:4] dst port
 *   [4:6] length (header + payload)
 *   [6:8] checksum (not stored — we don't validate checksums)
 * ------------------------------------------------------------------ */
static PyObject *
build_udp(const unsigned char *buf, int transport_offset)
{
    const unsigned char *t = buf + transport_offset;
    unsigned int src_port = BE16(t, 0);
    unsigned int dst_port = BE16(t, 2);
    unsigned int length   = BE16(t, 4);

    return PyObject_CallFunction(
        UDPHeader_cls, "III", src_port, dst_port, length
    );
}

/* ------------------------------------------------------------------
 * parse_packet: the public function exposed to Python.
 *
 * Python signature: parse_packet(data: bytes, timestamp: float) -> PacketInfo | None
 *
 * Mirrors the logic flow of parser.py:parse_packet() exactly:
 *   1. Reject if too short for Ethernet header
 *   2. Decode Ethernet, check EtherType
 *   3. If IPv4: decode IP header, compute transport offset
 *   4. Dispatch to TCP or UDP decoder based on IP protocol field
 *   5. Assemble and return a PacketInfo instance
 * ------------------------------------------------------------------ */
static PyObject *
py_parse_packet(PyObject *Py_UNUSED(self), PyObject *args)
{
    const unsigned char *buf;
    Py_ssize_t buflen;
    double timestamp;

    if (!PyArg_ParseTuple(args, "y#d", &buf, &buflen, &timestamp))
        return NULL;

    if (buflen < ETH_HEADER_LEN)
        Py_RETURN_NONE;

    PyObject *eth = build_ethernet(buf);
    if (!eth) return NULL;

    unsigned int ethertype = BE16(buf, 12);

    PyObject *py_timestamp = PyFloat_FromDouble(timestamp);
    PyObject *py_rawlen    = PyLong_FromSsize_t(buflen);

    PyObject *info = PyObject_CallFunction(
        PacketInfo_cls, "OOOOO",
        py_timestamp, py_rawlen, eth,
        Py_None, Py_None
    );
    Py_DECREF(py_timestamp);
    Py_DECREF(py_rawlen);
    Py_DECREF(eth);

    if (!info) return NULL;

    if (ethertype != ETH_TYPE_IPV4) {
        return info;
    }

    if (buflen < ETH_HEADER_LEN + MIN_IP_LEN) {
        return info;
    }

    int ip_header_len = 0;
    PyObject *ip = build_ipv4(buf, &ip_header_len);
    if (!ip) { Py_DECREF(info); return NULL; }

    if (PyObject_SetAttrString(info, "ip", ip) < 0) {
        Py_DECREF(ip); Py_DECREF(info); return NULL;
    }
    Py_DECREF(ip);

    int transport_offset = ETH_HEADER_LEN + ip_header_len;
    unsigned char protocol = buf[23];

    if (protocol == IP_PROTO_TCP && buflen >= transport_offset + MIN_TCP_LEN)
    {
        PyObject *tcp = build_tcp(buf, transport_offset);
        if (!tcp) { Py_DECREF(info); return NULL; }
        if (PyObject_SetAttrString(info, "tcp", tcp) < 0) {
            Py_DECREF(tcp); Py_DECREF(info); return NULL;
        }
        Py_DECREF(tcp);
    }
    else if (protocol == IP_PROTO_UDP && buflen >= transport_offset + MIN_UDP_LEN)
    {
        PyObject *udp = build_udp(buf, transport_offset);
        if (!udp) { Py_DECREF(info); return NULL; }
        if (PyObject_SetAttrString(info, "udp", udp) < 0) {
            Py_DECREF(udp); Py_DECREF(info); return NULL;
        }
        Py_DECREF(udp);
    }

    return info;
}

/* ------------------------------------------------------------------
 * Module method table and initialisation.
 *
 * PyMODINIT_FUNC is the entry point Python's import machinery calls
 * when loading the .so. We use it to:
 *   a) register parse_packet as a callable in the module namespace
 *   b) import the Python dataclass types we'll instantiate from C
 * ------------------------------------------------------------------ */
static PyMethodDef ParserMethods[] = {
    {
        "parse_packet",
        py_parse_packet,
        METH_VARARGS,
        "parse_packet(data, timestamp) -> PacketInfo | None\n\n"
        "C implementation of the packet protocol decoder.\n"
        "Identical interface to parser.py:parse_packet()."
    },
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef parser_c_module = {
    PyModuleDef_HEAD_INIT,
    "parser_c",
    NULL,
    -1,
    ParserMethods,
    NULL,
    NULL,
    NULL,
    NULL,
};

PyMODINIT_FUNC
PyInit_parser_c(void)
{
    PyObject *m = PyModule_Create(&parser_c_module);
    if (!m) return NULL;

    PyObject *parser_mod = PyImport_ImportModule("packet_sniffer.parser");
    if (!parser_mod) {
        Py_DECREF(m);
        return NULL;
    }

    PacketInfo_cls      = PyObject_GetAttrString(parser_mod, "PacketInfo");
    EthernetHeader_cls  = PyObject_GetAttrString(parser_mod, "EthernetHeader");
    IPHeader_cls        = PyObject_GetAttrString(parser_mod, "IPHeader");
    TCPHeader_cls       = PyObject_GetAttrString(parser_mod, "TCPHeader");
    UDPHeader_cls       = PyObject_GetAttrString(parser_mod, "UDPHeader");
    Py_DECREF(parser_mod);

    if (!PacketInfo_cls || !EthernetHeader_cls || !IPHeader_cls ||
        !TCPHeader_cls  || !UDPHeader_cls)
    {
        Py_DECREF(m);
        return NULL;
    }

    return m;
}
