import struct
import socket
from dataclasses import dataclass, field
from typing import Optional

# Ethernet Frame Types (IEEE 802.3)
ETH_TYPE_IPv4 = 0x0800

# IP Protocol Numbers (RFC 1700)
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

# TCP Flags (RFC 793)
TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10
TCP_FLAG_URG = 0x20
TCP_FLAG_ECE = 0x40
TCP_FLAG_CWR = 0x80

"""
IP Header Fields (RFC 791)
"""
@dataclass
class IPHeader:
    version: int
    header_len: int
    total_len: int
    ttl: int
    protocol: int
    src_ip: str
    dst_ip: str

"""
TCP Header Fields (RFC 793)
"""
@dataclass
class TCPHeader:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    data_offset: int
    flags: int
    window: int

    def flag_str(self) -> str:
        names = []
        for mask, name in (
            (TCP_FLAG_FIN, "FIN"),
            (TCP_FLAG_SYN, "SYN"),
            (TCP_FLAG_RST, "RST"),
            (TCP_FLAG_PSH, "PSH"),
            (TCP_FLAG_ACK, "ACK"),
            (TCP_FLAG_URG, "URG"),
            (TCP_FLAG_ECE, "ECE"),
            (TCP_FLAG_CWR, "CWR")
        ):
            if self.flags & mask:
                names.append(name)
        return ", ".join(names) if names else "NONE"

"""
UDP Header Fields (RFC 768)
"""
@dataclass
class UDPHeader:
    src_port: int
    dst_port: int
    length: int

"""
Packet Information 
"""
@dataclass
class PacketInfo:
    timestamp: float
    raw_len: int
    eth: EthernetHeader
    ip: Optional[IPHeader] = None
    tcp: Optional[TCPHeader] = None
    udp: Optional[UDPHeader] = None

# Format a MAC address as a string
def _format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)

# Parse Ethernet header from raw data
def parse_ethernet(data: bytes) -> EthernetHeader:
    dst_mac, src_mac, ether_type = struct.unpack("!6s6sH", data[0:14])
    return EthernetHeader(
        dst_mac=_format_mac(dst_mac),
        src_mac=_format_mac(src_mac),
        ether_type=ether_type
    )

# Parse IPv4 header from raw data
def parse_ipv4(data: bytes) -> IPHeader:
    offset = 14
    ver_ih1 = data[offset]
    version = ver_ih1 >> 4
    header_len = (ver_ih1 & 0x0F) * 4
    (total_len, ident, flags_frag, ttl, proto, checksum,
    src_raw, dst_raw) = struct.unpack("!HHHBBH4s4s", data[offset + 2:offset + 20])

    return IPHeader(
        version=version,
        header_len=header_len,
        total_len=total_len,
        ttl=ttl,
        protocol=proto,
        src_ip=socket.inet_ntoa(src_raw),
        dst_ip=socket.inet_ntoa(dst_raw)
    )


# TCP Header Fields (RFC 793)
def parse_tcp(data: bytes, ip_header_offset: int) -> TCPHeader:
    o = ip_header_offset
    (src_port, dst_port, seq, ack, offset_byte, flags_byte, window,
    checksum, urg_ptr) = struct.unpack("!HHLLBBHHH", data[o:o + 20])
    return TCPHeader(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack_num=ack,
        data_offset=data_offset
        flags=flags_byte
        window=window
    )

# UDP Header Fields (RFC 768)
def parse_udp(data: bytes, ip_header_offset: int) -> UDPHeader:
    o = ip_header_offset
    (src_port, dst_port, length, checksum) = struct.unpack("!HHHH", data[o:o + 8])
    return UDPHeader(
        src_port=src_port,
        dst_port=dst_port,
        length=length
    )

# Parse the entire packet
def parse_packet(data: bytes, timestamp: float) -> Optional[PacketInfo]:
    if len(data) < 14:
        return None

    eth = parse_ethernet(data)
    info = PacketInfo(
        timestamp=timestamp,
        raw_len = len(data),
        eth=eth
    )
    
    if eth.ehtertype != ETH_TYPE_IPV4:
        return info

    if len(data) < 34:
        return info

    ip = parse_ipv4(data)
    info.ip = ip

    transport_offset = 14 + info.header_len

    if ip.protocol == IP_PROTO_TCP and len(data) >= transport_offset + 20:
        info.tcp = parse_tcp(data, transport_offset)
    elif ip.protocol == IP_PROTO_UDP and len(data) >= transport_offset + 8:
        info.udp = parse_udp(data, transport_offset)

    return info