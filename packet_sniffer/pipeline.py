"""Bridge the capture producer to the parser and analysis consumer."""

import queue
import threading
from typing import Optional

from packet_sniffer.capture import PacketCapture, POISON_PILL, RawPacket
from packet_sniffer.parser import parse_packet
from packet_sniffer.engine import AnalysisEngine


class Pipeline:
    """Coordinate capture, parsing, and inline analysis through a bounded queue."""

    def __init__(self, iface: str, engine: AnalysisEngine, queue_size: int = 1000):
        self.in_queue: "queue.Queue[RawPacket]" = queue.Queue(maxsize=queue_size)
        self.capture = PacketCapture(iface=iface, out_queue=self.in_queue)
        self.engine = engine
        self._consumer_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Launch the consumer thread and begin packet capture."""
        self._consumer_thread = threading.Thread(
            target=self._consume_loop, name="analysis-consumer", daemon=True
        )
        self._consumer_thread.start()
        self.capture.start()

    def stop(self) -> None:
        """Request shutdown of both producer and consumer threads."""
        self._stop_event.set()
        self.capture.stop()
        if self._consumer_thread is not None:
            self._consumer_thread.join(timeout=3)

    def _consume_loop(self) -> None:
        """Parse queued frames and hand them to the analysis engine.

        The consumer thread blocks on the queue until a sentinel POISON_PILL is
        received from the capture producer during shutdown.
        """
        while True:
            item = self.in_queue.get()
            if item == POISON_PILL:
                break
            packet = parse_packet(item.data, item.timestamp)
            if packet is not None:
                self.engine.process(packet)

    def stats(self) -> dict:
        """Return lightweight runtime metrics for observability."""
        return {
            "packets_captured": self.capture.packets_captured,
            "packets_dropped": self.capture.packets_dropped,
            "packets_processed": self.engine.packets_processed,
            "alerts_raised": self.engine.alerts_raised,
            "queue_depth": self.in_queue.qsize(),
        }
