"""Minimal Ethernet, IPv4, TCP, and UDP packet parser for the sniffer.

This module parses raw Ethernet II frames and extracts IPv4, TCP, and UDP
headers for the packet analysis pipeline. It is intentionally lightweight and
only supports a subset of IPv4 traffic, avoiding fragmentation and non-IPv4
encapsulation formats.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
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


@dataclass
class EthernetHeader:
    """Standard Ethernet II header fields used for frame classification."""

    dst_mac: str
    src_mac: str
    ether_type: int


@dataclass
class IPHeader:
    """IPv4 header fields relevant to transport-layer parsing."""

    version: int
    header_len: int
    total_len: int
    ttl: int
    protocol: int
    src_ip: str
    dst_ip: str


@dataclass
class TCPHeader:
    """TCP header fields used by the threat detectors."""

    src_port: int
    dst_port: int
    seq: int
    ack_num: int
    data_offset: int
    flags: int
    window: int

    def flags_str(self) -> str:
        """Render the active TCP flags as a readable string."""
        names = []
        for mask, name in (
            (TCP_FLAG_FIN, "FIN"),
            (TCP_FLAG_SYN, "SYN"),
            (TCP_FLAG_RST, "RST"),
            (TCP_FLAG_PSH, "PSH"),
            (TCP_FLAG_ACK, "ACK"),
            (TCP_FLAG_URG, "URG"),
            (TCP_FLAG_ECE, "ECE"),
            (TCP_FLAG_CWR, "CWR"),
        ):
            if self.flags & mask:
                names.append(name)
        return ", ".join(names) if names else "NONE"

    def flag_str(self) -> str:
        """Backward-compatible alias for flags_str()."""
        return self.flags_str()


@dataclass
class UDPHeader:
    """UDP header fields used for lightweight protocol inspection."""

    src_port: int
    dst_port: int
    length: int


@dataclass
class PacketInfo:
    """Structured view of a parsed network packet for downstream analysis."""

    timestamp: float
    raw_len: int
    eth: EthernetHeader
    ip: Optional[IPHeader] = None
    tcp: Optional[TCPHeader] = None
    udp: Optional[UDPHeader] = None


def _format_mac(raw: bytes) -> str:
    """Format a binary MAC address as colon-separated hex."""
    return ":".join(f"{b:02x}" for b in raw)


def parse_ethernet(data: bytes) -> EthernetHeader:
    """Parse the 14-byte Ethernet II header from a raw frame."""
    dst_mac, src_mac, ether_type = struct.unpack("!6s6sH", data[0:14])
    return EthernetHeader(
        dst_mac=_format_mac(dst_mac),
        src_mac=_format_mac(src_mac),
        ether_type=ether_type,
    )


def parse_ipv4(data: bytes) -> IPHeader:
    """Parse the IPv4 header and normalize source and destination addresses.

    The first byte of the IPv4 header contains the version and Internet Header
    Length (IHL). IHL is expressed in 32-bit words, so it must be multiplied by
    four to obtain the header length in bytes.
    """
    offset = 14
    ver_ih1 = data[offset]
    version = ver_ih1 >> 4
    header_len = (ver_ih1 & 0x0F) * 4
    (total_len, _ident, _flags_frag, ttl, proto, _checksum, src_raw, dst_raw) = struct.unpack(
        "!HHHBBH4s4s", data[offset + 2 : offset + 20]
    )

    return IPHeader(
        version=version,
        header_len=header_len,
        total_len=total_len,
        ttl=ttl,
        protocol=proto,
        src_ip=socket.inet_ntoa(src_raw),
        dst_ip=socket.inet_ntoa(dst_raw),
    )


def parse_tcp(data: bytes, ip_header_offset: int) -> TCPHeader:
    """Parse a TCP header from the given transport offset in the frame.

    The data offset field is encoded in the upper 4 bits of the fifth TCP
    header byte and indicates the header length in 32-bit words.
    """
    o = ip_header_offset
    (src_port, dst_port, seq, ack, offset_byte, flags_byte, window, _checksum, _urg_ptr) = struct.unpack(
        "!HHLLBBHHH", data[o : o + 20]
    )
    data_offset = (offset_byte >> 4) * 4
    return TCPHeader(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack_num=ack,
        data_offset=data_offset,
        flags=flags_byte,
        window=window,
    )


def parse_udp(data: bytes, ip_header_offset: int) -> UDPHeader:
    """Parse a UDP header from the given transport offset in the frame."""
    o = ip_header_offset
    (src_port, dst_port, length, _checksum) = struct.unpack("!HHHH", data[o : o + 8])
    return UDPHeader(src_port=src_port, dst_port=dst_port, length=length)


def parse_packet(data: bytes, timestamp: float) -> Optional[PacketInfo]:
    """Parse a raw Ethernet frame into a structured PacketInfo object.

    Frames shorter than the Ethernet header are discarded. Non-IPv4 frames are
    returned with only Ethernet metadata, while IPv4 packets are further
    inspected for TCP/UDP transport headers.
    """
    if len(data) < 14:
        return None

    eth = parse_ethernet(data)
    info = PacketInfo(timestamp=timestamp, raw_len=len(data), eth=eth)

    if eth.ether_type != ETH_TYPE_IPV4:
        return info

    # Ensure the minimum IPv4 header and first transport header bytes are present.
    if len(data) < 34:
        return info

    ip = parse_ipv4(data)
    info.ip = ip

    transport_offset = 14 + ip.header_len

    if ip.protocol == IP_PROTO_TCP and len(data) >= transport_offset + 20:
        info.tcp = parse_tcp(data, transport_offset)
    elif ip.protocol == IP_PROTO_UDP and len(data) >= transport_offset + 8:
        info.udp = parse_udp(data, transport_offset)

    return info
