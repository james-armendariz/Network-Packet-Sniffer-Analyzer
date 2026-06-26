"""Alert propagation primitives used by the packet analysis pipeline."""

import sys
import time
from abc import ABC, abstractmethod
from typing import List

from packet_sniffer.detectors import Alert


class AlertObserver(ABC):
    """Interface for components that consume detector-generated alerts."""

    @abstractmethod
    def notify(self, alert: Alert) -> None:
        """Handle a newly raised alert.

        Implementations may route alerts to stdout, stderr, a log sink, or an
        in-memory collector depending on the deployment context.
        """
        raise NotImplementedError


class ConsoleAlerter(AlertObserver):
    """Render alerts to stderr with severity-aware color coding."""

    _COLORS = {"low": "\033[93m", "medium": "\033[91m", "high": "\033[1;95m"}
    _RESET = "\033[0m"

    def notify(self, alert: Alert) -> None:
        """Emit a human-readable alert line for interactive use.

        This implementation is intended for interactive debugging and
        development, not for production ingestion into a SIEM.
        """
        color = self._COLORS.get(alert.severity, "")
        ts = time.strftime("%H:%M:%S")
        print(
            f"{color}[{ts}] [{alert.severity.upper()}] [{alert.category}] "
            f"{alert.message}{self._RESET}",
            file=sys.stderr,
        )


class AlertPublisher:
    """Fan-out alert distributor for one or more alert observers."""

    def __init__(self) -> None:
        self._observers: List[AlertObserver] = []

    def subscribe(self, observer: AlertObserver) -> None:
        """Register a new observer to receive future alerts."""
        self._observers.append(observer)

    def publish(self, alert: Alert) -> None:
        """Dispatch an alert to every subscribed observer."""
        for obs in self._observers:
            obs.notify(alert)
