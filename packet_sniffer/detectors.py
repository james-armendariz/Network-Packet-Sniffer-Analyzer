from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

"""
Represents an alert for a detected threat.
"""
@dataclass
class Alert:
    severity: str
    category: str
    message: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None

"""
Common interface for all detectors.
"""
class Detector(ABC):
    name: str = "unamed_detector"

    # Inspect a network packet and return an alert if a potential 
    #threat is detected.
    @abstractmethod
    def inspect(self, packet: PacketInfo) -> Optional[Alert]:
        raise NotImplementedError

"""
Flags TCP packets with flag combinations that essentially never
occur in ligitimate traffic but are characteristic of well-known
stealth scanning techniques:
    - NULL scan (no TCP flags set)-
    - FIN scan (lone FIN flag)-
    - XMAS scan (FIN+PSH+URG)-
    - Contradictory SYN+FIN flags
"""
class StealthScanDetector(Detector):
    name = "stealth_scan"

    # Inspect a network packet for stealth scan attempts.
    def inspect(self, packet: PacketInfo) -> Optional[Alert]:
        if packet.tcp is None or packet.ip is None:
            return None

        flags = packet.tcp.flags
        flag_str = packet.tcp.flags_str()

        if flags == 0:
            return self._alert(packet, "NULL scan (no TCP flags set)", flag_str)

        if flags == TCP_FLAG_FIN:
            return self._alert(packet, "FIN scan (lone FIN flag)", flag_str)

        if flags == (TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG):
            return self._alert(packet, "XMAS scan (FIN+PSH+URG)", flag_str)

        if (flags & TCP_FLAG_SYN) and (flags & TCP_FLAG_FIN):
            return self._alert(packet, "Contradictory SYN+FIN flags", flag_str)

        return None

    # Create an alert for the detected threat.
    def _alert(self, packet: PacketInfo, reason: str, flag_str: str) -> Alert:
        return Alert(
            severity = "medium",
            category = self.name,
            message = f"{reason} from {packet.ip.src_ip} -> "
                      f"{packet.ip.dst_ip}:{packet.tcp.dst_port} {flags={flag_str}}",
            src_ip = packet.ip.src_ip,
            dst_ip = packet.ip.dst_ip,
            dst_port = packet.tcp.dst_port
        )