from typing import List

from packet_sniffer.parser import PacketInfo
from packet_sniffer.detectors import Detector
from packet_sniffer.alerts import AlertPublisher

# Analysis engine for processing network packets and detecting potential threats.
class AnalysisEngine:
    def __init__(self, detectors: List[Detector], publisher: AlertPublisher) -> None:
        self.detectors = detectors
        self.publisher = publisher
        self.packets_processed = 0
        self.alerts_raised = 0

    def process(self, packet: PacketInfo) -> None:
        self.packets_processed += 1
        for detector in self._detectors:
            alert = detector.inspect(packet)
            if alert is not None:
                self.alerts_raised += 1
                self._publisher.publish(alert)