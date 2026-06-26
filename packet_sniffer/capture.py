"""Raw packet capture support using Linux AF_PACKET sockets."""

import queue
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional

# Capture all Ethernet packet types on the selected interface.
ETH_P_ALL = 0x0003
# The Linux kernel will report frames up to this size in a single read.
RECV_BUFFER_SIZE = 65535
RECV_TIMEOUT = 1.0

# A sentinel value used to stop the downstream consumer thread cleanly.
POISON_PILL = object()


@dataclass
class RawPacket:
    """Container for a captured frame and its arrival timestamp."""

    data: bytes
    timestamp: float


class PacketCapture:
    """Producer thread that captures raw frames from a network interface."""

    def __init__(self, iface: str, out_queue: "queue.Queue"):
        self.iface = iface
        self.out_queue = out_queue
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self.packets_captured = 0
        self.packets_dropped = 0

    def start(self) -> None:
        """Open the raw socket and launch the capture loop in a background thread."""
        # AF_PACKET sockets capture raw Ethernet frames directly from the link.
        # This interface is Linux-specific and usually requires elevated privileges.
        self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        self._sock.bind((self.iface, 0))
        self._sock.settimeout(RECV_TIMEOUT)

        self._thread = threading.Thread(target=self._run, name="capture-producer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the producer to stop and release the socket resources."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=RECV_TIMEOUT + 1)
        if self._sock is not None:
            self._sock.close()
        self.out_queue.put(POISON_PILL)

    def _run(self) -> None:
        """Continuously read from the socket until the stop event is set."""
        while not self._stop_event.is_set():
            if self._sock is None:
                break
            try:
                data, _addr = self._sock.recvfrom(RECV_BUFFER_SIZE)
            except socket.timeout:
                continue
            except OSError:
                break

            self.packets_captured += 1
            self._enqueue(RawPacket(data=data, timestamp=time.time()))

    def _enqueue(self, item: RawPacket) -> None:
        """Push a frame into the bounded work queue, dropping the oldest item if needed."""
        try:
            self.out_queue.put_nowait(item)
        except queue.Full:
            # Backpressure handling: preserve the newest captured frame when the
            # queue is full by discarding the oldest queued item first.
            try:
                self.out_queue.get_nowait()
                self.packets_dropped += 1
            except queue.Empty:
                pass
            try:
                self.out_queue.put_nowait(item)
            except queue.Full:
                self.packets_dropped += 1
