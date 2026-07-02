"""
test_traffic_spike_detector.py — Unit tests for TrafficSpikeDetector.

All timestamps are injected manually so we can simulate seconds of traffic
in milliseconds of test time, with no live sockets or real waiting.
"""

import sys
import os
from typing import Iterable, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from packet_sniffer.detectors import Alert, TrafficSpikeDetector
from packet_sniffer.parser import (
    PacketInfo,
    EthernetHeader,
    IPHeader,
    TCPHeader,
    TCP_FLAG_SYN,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_packet(src_ip: str = "10.0.0.1", timestamp: float = 0.0) -> PacketInfo:
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
        dst_ip="192.168.1.1",
    )
    tcp = TCPHeader(
        src_port=54321,
        dst_port=80,
        seq=0,
        ack_num=0,
        data_offset=20,
        flags=TCP_FLAG_SYN,
        window=65535,
    )
    return PacketInfo(timestamp=timestamp, raw_len=40, eth=eth, ip=ip, tcp=tcp)


def _simulate_traffic(
    detector: TrafficSpikeDetector,
    src_ip: str,
    pkts_per_second: float,
    duration_seconds: float,
    start_time: float = 0.0,
    time_step: float = 0.01,
) -> List[PacketInfo]:
    """
    Send a stream of packets at a given rate by spacing timestamps evenly.
    Returns all alerts fired during this period.
    """
    alerts: List[PacketInfo] = []
    t = start_time
    end_time = start_time + duration_seconds
    interval = 1.0 / pkts_per_second if pkts_per_second > 0 else 1.0

    while t < end_time:
        pkt = _make_packet(src_ip=src_ip, timestamp=t)
        alert = detector.inspect(pkt)
        if alert:
            alerts.append(alert)
        t += interval

    return alerts


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_no_alert_during_warmup():
    """
    No alerts should fire during the warmup period, even if traffic is
    already elevated. The baseline is still stabilising.
    """
    detector = TrafficSpikeDetector(
        min_samples=5, spike_multiplier=2.0, cooldown_seconds=0,
        global_track=False, per_source=True,
    )
    # Send 100 pkt/s for 4 seconds — below min_samples=5 ticks
    alerts = _simulate_traffic(detector, "10.0.0.1", pkts_per_second=100, duration_seconds=4.0)
    assert len(alerts) == 0, "Should not alert during warmup period"


def test_spike_detected_after_warmup():
    """
    Normal traffic followed by a 10× surge should trigger an alert
    once the baseline has warmed up.
    """
    detector = TrafficSpikeDetector(
        alpha=0.125, spike_multiplier=3.0, min_samples=5,
        cooldown_seconds=0, global_track=False, per_source=True,
    )
    # Establish a normal baseline: 10 pkt/s for 10 seconds
    _simulate_traffic(detector, "10.0.0.1", pkts_per_second=10, duration_seconds=10.0)
    # Surge to 200 pkt/s for 5 seconds (20× normal — well above 3× threshold)
    alerts = _simulate_traffic(detector, "10.0.0.1", pkts_per_second=200,
                                duration_seconds=5.0, start_time=10.0)
    assert len(alerts) >= 1, "Spike well above threshold should have triggered alert"
    assert alerts[0].category == "traffic_spike"
    assert "10.0.0.1" in alerts[0].message


def test_normal_traffic_never_alerts():
    """
    Stable traffic at a consistent rate should never cross its own baseline
    by the spike_multiplier, so no alert should fire.
    """
    detector = TrafficSpikeDetector(
        alpha=0.125, spike_multiplier=3.0, min_samples=5,
        cooldown_seconds=0, global_track=False, per_source=True,
    )
    # Steady 50 pkt/s for 30 seconds — always consistent, never spikes
    alerts = _simulate_traffic(detector, "10.0.0.2", pkts_per_second=50, duration_seconds=30.0)
    assert len(alerts) == 0, "Stable traffic should never trigger a spike alert"


def test_cooldown_suppresses_repeat_alerts():
    """
    After one spike alert, subsequent packets within the cooldown window
    must not generate additional alerts.
    """
    detector = TrafficSpikeDetector(
        alpha=0.125, spike_multiplier=2.0, min_samples=5,
        cooldown_seconds=60.0, global_track=False, per_source=True,
    )
    # Warmup
    _simulate_traffic(detector, "10.0.0.3", pkts_per_second=10, duration_seconds=10.0)
    # First spike — triggers alert
    _simulate_traffic(detector, "10.0.0.3", pkts_per_second=500,
                       duration_seconds=3.0, start_time=10.0)
    # Continued spike within cooldown window
    alerts = _simulate_traffic(detector, "10.0.0.3", pkts_per_second=500,
                                duration_seconds=5.0, start_time=13.0)
    assert len(alerts) == 0, "Cooldown should suppress re-alerts within 60 seconds"


def test_global_tracker_fires_on_aggregate_surge():
    """
    The global tracker should fire when aggregate traffic surges, even if
    no single source individually exceeds the per-source threshold.
    """
    detector = TrafficSpikeDetector(
        alpha=0.125, spike_multiplier=3.0, min_samples=5,
        cooldown_seconds=0, global_track=True, per_source=False,
    )
    # Many sources each sending modest amounts — warmup
    for i in range(10):
        _simulate_traffic(detector, f"10.0.0.{i+1}", pkts_per_second=5,
                           duration_seconds=10.0)

    # Now all sources send 50× more (massive aggregate surge)
    alerts = []
    for i in range(10):
        batch = _simulate_traffic(detector, f"10.0.0.{i+1}", pkts_per_second=250,
                                   duration_seconds=5.0, start_time=10.0)
        alerts.extend(batch)

    assert len(alerts) >= 1, "Global tracker should detect aggregate surge"
    assert any("global" in a.message.lower() for a in alerts)


def test_two_sources_tracked_independently():
    """
    A spike from one source should not affect the baseline of another.
    """
    detector = TrafficSpikeDetector(
        alpha=0.125, spike_multiplier=3.0, min_samples=5,
        cooldown_seconds=0, global_track=False, per_source=True,
    )
    # Both sources warmup at 10 pkt/s
    _simulate_traffic(detector, "10.0.0.10", pkts_per_second=10, duration_seconds=10.0)
    _simulate_traffic(detector, "10.0.0.11", pkts_per_second=10, duration_seconds=10.0)

    # Only source .10 spikes
    attacker_alerts = _simulate_traffic(detector, "10.0.0.10", pkts_per_second=300,
                                         duration_seconds=5.0, start_time=10.0)
    legit_alerts = _simulate_traffic(detector, "10.0.0.11", pkts_per_second=10,
                                      duration_seconds=5.0, start_time=10.0)

    assert len(attacker_alerts) >= 1, "Attacker spike should be detected"
    assert len(legit_alerts) == 0, "Legitimate host should not be flagged"


def test_ewma_baseline_adapts_to_gradual_increase():
    """
    A gradual ramp-up in traffic should not trigger an alert, because the
    EWMA baseline adapts alongside it. Only a sudden jump should alert.
    """
    detector = TrafficSpikeDetector(
        alpha=0.125, spike_multiplier=3.0, min_samples=5,
        cooldown_seconds=0, global_track=False, per_source=True,
    )
    # Gradually increase: 10 -> 20 -> 40 -> 80 pkt/s, 5 seconds each
    alerts = []
    for rate, t_start in [(10, 0), (20, 5), (40, 10), (80, 15)]:
        batch = _simulate_traffic(detector, "10.0.0.20", pkts_per_second=rate,
                                   duration_seconds=5.0, start_time=float(t_start))
        alerts.extend(batch)

    # Sudden 10× jump from 80 to 800 pkt/s — should alert
    spike_alerts = _simulate_traffic(detector, "10.0.0.20", pkts_per_second=800,
                                      duration_seconds=3.0, start_time=20.0)

    assert len(alerts) == 0, "Gradual ramp should not trigger spike alerts"
    assert len(spike_alerts) >= 1, "Sudden jump after gradual ramp should trigger alert"


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
