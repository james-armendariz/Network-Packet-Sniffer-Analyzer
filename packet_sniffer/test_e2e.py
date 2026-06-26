import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from packet_sniffer.pipeline import Pipeline
from packet_sniffer.engine import AnalysisEngine
from packet_sniffer.detectors import StealthScanDetector
from packet_sniffer.alerts import AlertPublisher, AlertObserver
from packet_sniffer.parser import TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_URG
from packet_sniffer.tests.send_test_packet import send_tcp_packet


class CollectingAlerter(AlertObserver):
    """Test double that just records alerts instead of printing them."""
    def __init__(self):
        self.alerts = []

    def notify(self, alert):
        self.alerts.append(alert)


def test_xmas_scan_detected_on_live_loopback():
    publisher = AlertPublisher()
    collector = CollectingAlerter()
    publisher.subscribe(collector)

    engine = AnalysisEngine(detectors=[StealthScanDetector()], publisher=publisher)
    pipeline = Pipeline(iface="lo", engine=engine, queue_size=100)

    pipeline.start()
    time.sleep(0.5)  # let the capture thread actually bind and start polling

    xmas_flags = TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG
    send_tcp_packet(dst_ip="127.0.0.1", dst_port=9999, flags=xmas_flags)

    time.sleep(1.0)  # give the consumer thread time to process the queue
    pipeline.stop()

    stats = pipeline.stats()
    print(f"Stats: {stats}")
    print(f"Alerts collected: {len(collector.alerts)}")
    for a in collector.alerts:
        print(f"  -> {a.message}")

    assert stats["packets_captured"] >= 1, "No packets were captured on loopback at all"
    assert len(collector.alerts) >= 1, "XMAS scan packet was not flagged"
    assert collector.alerts[0].category == "stealth_scan"
    assert "XMAS" in collector.alerts[0].message


if __name__ == "__main__":
    test_xmas_scan_detected_on_live_loopback()
    print("\nPASS: test_xmas_scan_detected_on_live_loopback")
