"""
pipeline.py — Wires the producer (capture.py) to the consumer
(parser.py -> engine.py) via the bounded queue.

This is the only file that needs to change if we later move to multiple
sharded consumer threads (per our architecture discussion) — the rest
of the system (capture, parser, detectors, alerts) stays untouched.
"""

import queue
import threading
from typing import Optional

from packet_sniffer.capture import PacketCapture, POISON_PILL, RawPacket
from packet_sniffer.engine import AnalysisEngine

# Prefer the C extension parser for throughput; fall back to pure Python
# transparently if the .so hasn't been compiled yet (e.g. on a fresh clone).
try:
    from packet_sniffer.parser_c import parse_packet
    _PARSER_BACKEND = "C extension"
except ImportError:
    from packet_sniffer.parser import parse_packet
    _PARSER_BACKEND = "Python (pure)"


class Pipeline:
    def __init__(self, iface: str, engine: AnalysisEngine, queue_size: int = 1000):
        self.in_queue: "queue.Queue[RawPacket]" = queue.Queue(maxsize=queue_size)
        self.capture = PacketCapture(iface=iface, out_queue=self.in_queue)
        self.engine = engine
        self._consumer_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._consumer_thread = threading.Thread(
            target=self._consume_loop, name="analysis-consumer", daemon=True
        )
        self._consumer_thread.start()
        self.capture.start()

    def stop(self) -> None:
        self._stop_event.set()
        self.capture.stop()  # also pushes the poison pill that wakes the consumer
        if self._consumer_thread is not None:
            self._consumer_thread.join(timeout=3)

    def _consume_loop(self) -> None:
        while True:
            item = self.in_queue.get()
            if item is POISON_PILL:
                break
            packet = parse_packet(item.data, item.timestamp)
            if packet is not None:
                self.engine.process(packet)

    def stats(self) -> dict:
        return {
            "parser_backend": _PARSER_BACKEND,
            "packets_captured": self.capture.packets_captured,
            "packets_dropped": self.capture.packets_dropped,
            "packets_processed": self.engine.packets_processed,
            "alerts_raised": self.engine.alerts_raised,
            "queue_depth": self.in_queue.qsize(),
        }
