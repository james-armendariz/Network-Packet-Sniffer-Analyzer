import queue
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional

# define the Ethernet protocol type for all packets
ETH_P_ALL = 0x0003
# IP Header: 16 bits => 2^16 - 1 = 65535
RECV_BUFFER_SIZE = 65535
RECV_TIMEOUT = 1.0

# When this object is received, the thread should stop.
POISON_PILL = object()

@dataclass
class RawPacket:
    data: bytes
    timestamp: float

# Class to capture raw network packets.
class PacketCapture:
    def __init__(self, iface: str, out_queue: "queue.Queue"):
        self.iface = iface
        self.out_queue = out_queue
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self.packets_captured = 0
        self.packets_dropped = 0

    # Start the packet capture thread.
    def start(self) -> None:
        self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.nthos(ETH_P_ALL))
        self._sock.bind((self.iface, 0))
        self._sock.settimeout(RECV_TIMEOUT)

        self._thread = threading.Thread(target=self._run, name="capture-producer", daemon=True)
        self._thread.start()

    # Stop the packet capture thread.
    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=RECV_TIMEOUT + 1)
        if self._sock is not None:
            self._sock.close()
        self.out_queue.put(POISON_PILL)

    # Run the packet capture loop.
    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                data, _addr = self._sock.recvfrom(RECV_BUFFER_SIZE)
            except socket.timeout:
                continue
            except OSError:
                break
            self.packets_captured += 1
            self._enqueue(RawPacket(data=data, timestamp=time.time()))

    # Enqueue a packet to the output queue.
    def _enqueue(self, item: RawPacket) -> None:
        try:
            self.out_queue.put_nowait(item)
        except queue.Full:
            try:
                self.out_queue.get_nowait()
                self.packets_dropped += 1
            except queue.Empty:
                pass
            try:
                self.out_queue.put_nowait(item)
            except queue.Full:
                self.packets_dropped += 1