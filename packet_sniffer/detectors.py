"""Threat detectors for identifying suspicious packet patterns."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from packet_sniffer.parser import (
    PacketInfo,
    TCP_FLAG_FIN,
    TCP_FLAG_PSH,
    TCP_FLAG_SYN,
    TCP_FLAG_URG,
)


@dataclass
class Alert:
    """Structured record describing a security-relevant observation."""

    severity: str
    category: str
    message: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None


class Detector(ABC):
    """Base class for all packet inspection logic."""

    name: str = "unamed_detector"

    @abstractmethod
    def inspect(self, packet: PacketInfo) -> Optional[Alert]:
        """Return an alert when the packet matches a known suspicious pattern."""
        raise NotImplementedError


class StealthScanDetector(Detector):
    """Flag TCP packets matching classic stealth-scanning signatures.

    Certain flag combinations are rarely seen in normal traffic but are common
    in reconnaissance activity. The detector focuses on NULL, FIN, XMAS, and
    contradictory SYN/FIN scans because those are highly indicative of probing.
    """

    name = "stealth_scan"

    def inspect(self, packet: PacketInfo) -> Optional[Alert]:
        """Inspect a packet and raise an alert for suspicious TCP flags.

        These signatures are not absolute proof of an attack, but they are strong
        heuristic indicators when observed on network ingress or internal scans.
        """
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

    def _alert(self, packet: PacketInfo, reason: str, flag_str: str) -> Alert:
        """Create a standardized alert payload for a detection event."""
        return Alert(
            severity="medium",
            category=self.name,
            message=(
                f"{reason} from {packet.ip.src_ip} -> {packet.ip.dst_ip}:"
                f"{packet.tcp.dst_port} flags={flag_str}"
            ),
            src_ip=packet.ip.src_ip,
            dst_ip=packet.ip.dst_ip,
            dst_port=packet.tcp.dst_port,
        )
