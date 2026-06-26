"""Core analysis engine that routes parsed packets to detectors."""

from typing import List

from packet_sniffer.parser import PacketInfo
from packet_sniffer.detectors import Detector
from packet_sniffer.alerts import AlertPublisher


class AnalysisEngine:
    """Coordinate packet inspection and alert publication for the pipeline."""

    def __init__(self, detectors: List[Detector], publisher: AlertPublisher) -> None:
        self.detectors = detectors
        self.publisher = publisher
        self.packets_processed = 0
        self.alerts_raised = 0

    def process(self, packet: PacketInfo) -> None:
        """Inspect a parsed packet with every configured detector.

        The engine is intentionally simple: it performs synchronous, serial
        inspection and publishes the first matching alert from each detector.
        This avoids ordering dependencies inside the detector chain.
        """
        self.packets_processed += 1
        for detector in self.detectors:
            alert = detector.inspect(packet)
            if alert is not None:
                self.alerts_raised += 1
                self.publisher.publish(alert)
