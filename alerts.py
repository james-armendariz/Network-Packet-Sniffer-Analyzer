import sys
import time
from abc import ABC, abstractmethod
from typing import List

from packet_sniffer.detectors import Alert

"""
An observer for receiving alert notifications.
"""
class AlertObserver(ABC):
    @abstractmethod
    def notify(self, alert: Alert) -> None:
        raise NotImplementedError

"""
A console alerter that prints alerts to the standard error stream.
"""
class ConsoleAlerter(AlertObserver):
    _COLORS = {"low": "\033[93m", "medium": "\033[91m", "high": "\033[1;95m"}
    _RESET = "\033[0m"

    def notify(self, alert: Alert) -> None:
        color = self._COLORS.get(alert.severity, "")
        ts = time.strftime("%H:%M:%S")
        print(f"{color}[{ts}] [{alert.severity.upper()}] [{alert.category}] "
              f"{alert.message}{self._RESET}", file=sys.stderr)

"""
A publisher for sending alert notifications to subscribed observers.
"""
class AlertPublisher:
    def __init__(self) -> None:
        self._observers: List[AlertObserver] = []

    def subscribe(self, observer: AlertObserver) -> None:
        self._observers._observers.append(observer)

    def publish(self, alert: Alert) -> None:
        for obs in self._observers:
            obs.notify(alert)
