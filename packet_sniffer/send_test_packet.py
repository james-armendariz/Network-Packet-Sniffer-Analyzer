"""Helpers for crafting and transmitting a minimal TCP packet for testing."""

import socket
import struct


def _checksum16(data: bytes) -> int:
    """Calculate the standard Internet checksum over a byte sequence.

    This implements the one's complement 16-bit checksum used by IPv4 and TCP.
    The payload is padded to an even byte count so 16-bit words can be summed
    without misalignment.
    """
    if len(data) % 2:
        data += b"\x00"
    total = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    return ~total & 0xFFFF


def _build_ip_header(src_ip: str, dst_ip: str, payload_len: int) -> bytes:
    """Build a synthetic IPv4 header with a computed checksum."""
    version_ihl = (4 << 4) | 5
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        20 + payload_len,
        0,
        0,
        64,
        socket.IPPROTO_TCP,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    csum = _checksum16(header)
    return header[:10] + struct.pack("!H", csum) + header[12:]


def _build_tcp_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: int) -> bytes:
    """Build a TCP header with a checksum computed over the pseudo-header.

    TCP checksum calculation includes the IP pseudo-header to protect the
    source/destination addresses and protocol number together with the TCP
    segment contents.
    """
    seq, ack, window, urg_ptr = 0, 0, 65535, 0
    data_offset_byte = 5 << 4

    header_no_checksum = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset_byte,
        flags,
        window,
        0,
        urg_ptr,
    )

    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        len(header_no_checksum),
    )
    csum = _checksum16(pseudo_header + header_no_checksum)

    return header_no_checksum[:16] + struct.pack("!H", csum) + header_no_checksum[18:]


def send_tcp_packet(
    dst_ip: str,
    dst_port: int,
    flags: int,
    src_ip: str = "127.0.0.1",
    src_port: int = 51234,
) -> None:
    """Transmit a crafted TCP packet to the requested destination."""
    tcp_header = _build_tcp_header(src_ip, dst_ip, src_port, dst_port, flags)
    ip_header = _build_ip_header(src_ip, dst_ip, len(tcp_header))
    packet = ip_header + tcp_header

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.sendto(packet, (dst_ip, dst_port))
    sock.close()

