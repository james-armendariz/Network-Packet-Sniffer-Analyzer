import struct
import socket
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from packet_sniffer import parser

def build_eth_frame(payload: bytes, ethertype: int = parser.ETH_TYPE_IPV4) -> bytes:
    dst_mac = bytes.fromhex("aabbccddeeff")
    src_mac = bytes.fromhex("112233445566")
    eth_header = struct.pack("!6s6sH", dst_mac, src_mac, ethertype)
    return eth_header + payload

def build_ipv4_header(proto: int, src_ip: str, dst_ip: str, payload_len: int) -> bytes:
    version_ih1 = (4 << 4) | 5
    total_len = 20 + payload_len
    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ih1, 0, total_len, 0, 0,
        64, proto, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )

def build_tcp_header(src_port: int, dst_port: int, flags: int, payload_len: int = 0) -> bytes:
    data_offset_bytes = (5 << 4)
    return struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        1000,
        0,
        data_offset_bytes,
        flags,
        65535,
        0,
        0,
    )

def build_udp_header(src_port: int, dst_port: int, payload_len: int) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, 8 + payload_len, 0)

def test_ethernet_fields():
    frame = build_ether_frame(b"\x00" * 20)
    info = parser.parse_packet(frame, timestamp=0.0)
    assert info is not None
    assert info.eth.dst_mac == "aa:bb:cc:dd:ee:ff"
    assert info.eth.src_mac == "11:22:33:44:55:66"
    assert info.eth.ethertype == parser.ETH_TYPE_IPV4

def test_ipv4_fields():
    ip_header = build_ipv4_header(parser.IP_PROTO_TCP, "10.0.0.1", "10.0.0.2", 20)
    frame = build_eth_frame(ip_header + b"\x00" * 20)
    info = parser.parse_packet(frame, timestamp=0.0)
    assert info.ip.version == 4
    assert info.ip.header_len == 20
    assert info.ip.src_ip == "10.0.0.1"
    assert info.ip.dst_ip == "10.0.0.2"
    assert info.ip.protocol == parser.IP_PROTO_TCP

def test_tcp_fields_and_flags():
    tcp_header = build_tcp_header(54321, 80, parser.TCP_FLAG_SYN)
    ip_header = build_ipv4_header(parser.IP_PROTO_TCP, "10.0.0.1", "10.0.0.2", len(tcp_header))
    frame = build_eth_frame(ip_header + tcp_header)
    info = parser.parse_packet(frame, timestamp=0.0)
    assert info.tcp is not None
    assert info.tcp.src_port == 54321
    assert info.tcp.dst_port == 80
    assert info.tcp.flags == parser.TCP_FLAG_SYN
    assert info.tcp.flag_str() == "SYN"
    assert info.tcp.data_offset == 20

def test_tcp_xmas_scan_flags():
    flags = parser.TCP_FLAG_FIN | parser.TCP_FLAG_PSH | parser.TCP_FLAG_URG
    tcp_header = build_tcp_header(11111, 22, flags)
    ip_header = build_ipv4_header(parser.IP_PROTO_TCP, "192.168.1.5", "192.168.1.10", len(tcp_header))
    frame = build_eth_frame(ip_header + tcp_header)
    info = parser.parse_packet(frame, timestamp=0.0)
    assert info.tcp.flag_str() == "FIN,PSH,URG"

def test_udp_fields():
    udp_header = build_udp_header(53, 33445, 0)
    ip_header = build_ipv4_header(parser.IP_PROTO_UDP, "8.8.8.8", "10.0.0.5", len(udp_header))
    frame = build_eth_frame(ip_header + udp_header)
    info = parser.parse_packet(frame, timestamp=0.0)
    assert info.udp is not None
    assert info.udp.src_port == 53
    assert info.udp.dst_port == 33445
    assert info.udp.length == 8

def test_truncated_frame_returns_none():
    assert parser.parse_packet(b"\x00" * 5, timestamp=0.0) is None

def test_non_ipv4_ethertype_stops_gracefully():
    arp_ethertype = 0x0806
    frame = build_eth_frame(b"\x00" * 28, ethertype=arp_ethertype)
    info = parser.parse_packet(frame, timestamp=0.0)
    assert info is not None
    assert info.ip is None

if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
        passed += 1
    print(f"\n{passed}/{len(tests)} tests passed")