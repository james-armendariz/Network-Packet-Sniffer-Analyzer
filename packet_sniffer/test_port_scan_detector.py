"""
test_port_scan_detector.py — Unit tests for PortScanDetector.

All tests use synthetic PacketInfo objects (no live sockets), so they
run without root privileges and are fully deterministic. Timestamps are
injected manually so we can simulate time passing without actually waiting.
"""

import sys
import os
from typing import Iterable, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from packet_sniffer.detectors import Alert, PortScanDetector
from packet_sniffer.parser import (
    PacketInfo,
    EthernetHeader,
    IPHeader,
    TCPHeader,
    TCP_FLAG_SYN,
    TCP_FLAG_ACK,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_packet(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    flags: int = TCP_FLAG_SYN,
    timestamp: float = 0.0,
) -> PacketInfo:
    """Build a minimal PacketInfo with just enough fields for PortScanDetector."""
    eth = EthernetHeader(
        dst_mac="ff:ff:ff:ff:ff:ff",
        src_mac="aa:bb:cc:dd:ee:ff",
        ether_type=0x0800,
    )
    ip = IPHeader(
        version=4,
        header_len=20,
        total_len=40,
        ttl=64,
        protocol=6,
        src_ip=src_ip,
        dst_ip=dst_ip,
    )
    tcp = TCPHeader(
        src_port=54321,
        dst_port=dst_port,
        seq=0,
        ack_num=0,
        data_offset=20,
        flags=flags,
        window=65535,
    )
    return PacketInfo(timestamp=timestamp, raw_len=40, eth=eth, ip=ip, tcp=tcp)


def _send_syn_burst(
    detector: PortScanDetector,
    src_ip: str,
    dst_ip: str,
    ports: Iterable[int],
    base_time: float = 0.0,
) -> List[Alert]:
    """Send SYN packets to the given ports and return any alerts fired."""
    alerts: List[Alert] = []
    for i, port in enumerate(ports):
        pkt = _make_packet(src_ip, dst_ip, port, timestamp=base_time + i * 0.1)
        alert = detector.inspect(pkt)
        if alert:
            alerts.append(alert)
    return alerts


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_vertical_scan_detected():
    """Hitting port_threshold distinct ports on one host fires a vertical alert."""
    detector = PortScanDetector(port_threshold=15, window_seconds=60, cooldown_seconds=0)
    alerts = _send_syn_burst(detector, "10.0.0.1", "192.168.1.5", range(1, 20))
    assert len(alerts) >= 1
    assert alerts[0].category == "port_scan"
    assert "Vertical" in alerts[0].message
    assert "10.0.0.1" in alerts[0].message


def test_vertical_scan_below_threshold_no_alert():
    """Fewer contacts than port_threshold must not fire."""
    detector = PortScanDetector(port_threshold=15, window_seconds=60, cooldown_seconds=0)
    alerts = _send_syn_burst(detector, "10.0.0.2", "192.168.1.5", range(1, 10))
    assert len(alerts) == 0


def test_horizontal_scan_detected():
    """Hitting host_threshold distinct hosts on one port fires a horizontal alert."""
    detector = PortScanDetector(host_threshold=20, window_seconds=60, cooldown_seconds=0)
    alerts = []
    for i in range(25):
        dst_ip = f"192.168.1.{i + 1}"
        pkt = _make_packet("10.0.0.3", dst_ip, 22, timestamp=float(i))
        alert = detector.inspect(pkt)
        if alert:
            alerts.append(alert)
    assert len(alerts) >= 1
    assert "Horizontal" in alerts[0].message
    assert alerts[0].dst_port == 22


def test_horizontal_scan_below_threshold_no_alert():
    """Fewer distinct hosts than host_threshold must not fire."""
    detector = PortScanDetector(host_threshold=20, window_seconds=60, cooldown_seconds=0)
    alerts = []
    for i in range(10):
        dst_ip = f"192.168.1.{i + 1}"
        pkt = _make_packet("10.0.0.4", dst_ip, 22, timestamp=float(i))
        alert = detector.inspect(pkt)
        if alert:
            alerts.append(alert)
    assert len(alerts) == 0


def test_cooldown_suppresses_repeated_alerts():
    """After one alert fires, subsequent packets within cooldown must not re-alert."""
    detector = PortScanDetector(port_threshold=5, window_seconds=60, cooldown_seconds=30)
    # Trigger the first alert
    _send_syn_burst(detector, "10.0.0.5", "192.168.1.10", range(1, 10))
    # Send more packets while still within cooldown
    alerts = _send_syn_burst(detector, "10.0.0.5", "192.168.1.10", range(10, 20), base_time=5.0)
    assert len(alerts) == 0, "Cooldown should suppress re-alerts during ongoing scan"


def test_cooldown_resets_after_expiry():
    """After the cooldown period, a second alert should be allowed."""
    detector = PortScanDetector(port_threshold=5, window_seconds=60, cooldown_seconds=10)
    # First burst — triggers alert, sets alerted_at = ~0
    _send_syn_burst(detector, "10.0.0.6", "192.168.1.11", range(1, 10), base_time=0.0)
    # Second burst — well past the 10s cooldown
    alerts = _send_syn_burst(detector, "10.0.0.6", "192.168.1.11", range(10, 20), base_time=50.0)
    assert len(alerts) >= 1, "Alert should re-fire after cooldown expires"


def test_non_syn_packets_are_ignored():
    """ACK, PSH, RST etc. packets should not contribute to port-scan state."""
    detector = PortScanDetector(port_threshold=5, window_seconds=60, cooldown_seconds=0)
    alerts = []
    for port in range(1, 20):
        # SYN+ACK (a server reply) — should be ignored
        pkt = _make_packet("10.0.0.7", "192.168.1.12", port,
                            flags=TCP_FLAG_SYN | TCP_FLAG_ACK, timestamp=float(port))
        alert = detector.inspect(pkt)
        if alert:
            alerts.append(alert)
    assert len(alerts) == 0, "SYN+ACK (server reply) should never trigger a scan alert"


def test_memory_eviction_removes_expired_state():
    """
    After the sweep interval, buckets older than the window should be evicted.
    This test verifies that old state doesn't persist and doesn't falsely
    contribute to a new window's count.
    """
    detector = PortScanDetector(port_threshold=15, window_seconds=60, cooldown_seconds=0)

    # Send 10 SYNs at t=0 (not enough to trigger by themselves)
    _send_syn_burst(detector, "10.0.0.8", "192.168.1.13", range(1, 11), base_time=0.0)
    assert "10.0.0.8" in detector._state

    # Jump to t=200 (well past window + sweep interval). The next packet
    # forces a sweep that should evict the stale state for this source.
    pkt = _make_packet("10.0.0.9", "192.168.1.99", 80, timestamp=200.0)
    detector.inspect(pkt)  # triggers _maybe_sweep on a different source

    # Force sweep directly by moving last_sweep back
    detector._last_sweep = 0
    pkt2 = _make_packet("10.0.0.8", "192.168.1.13", 9999, timestamp=200.0)
    detector.inspect(pkt2)

    # The old buckets at t≈0 should have been swept; only the t=200 bucket remains
    state = detector._state.get("10.0.0.8")
    if state:
        total_contacts = sum(len(v) for v in state.vertical.values())
        assert total_contacts <= 1, \
            f"Expected eviction to clear old state, but {total_contacts} contacts remain"


def test_two_sources_tracked_independently():
    """Two different source IPs should not interfere with each other's state."""
    detector = PortScanDetector(port_threshold=15, window_seconds=60, cooldown_seconds=0)
    # Attacker hits 18 ports
    attacker_alerts = _send_syn_burst(detector, "1.2.3.4", "192.168.1.1", range(1, 19))
    # Legitimate host hits 5 ports (normal application behavior)
    legit_alerts = _send_syn_burst(detector, "10.0.0.100", "192.168.1.1", range(80, 85))
    assert len(attacker_alerts) >= 1
    assert len(legit_alerts) == 0


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"PASS: {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {t.__name__} — {e}")
    print(f"\n{passed}/{len(tests)} tests passed.")
