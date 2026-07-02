"""
detectors.py — Anomaly detection strategies.

Strategy pattern: every detector implements the same `inspect(packet)`
interface, so the analysis engine doesn't need to know anything about
*how* a given detector works internally. Adding a new detector means
writing a new class here and registering it in the engine — nothing
else in the system needs to change.
"""

from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple
import time

from packet_sniffer.parser import PacketInfo, TCP_FLAG_FIN, TCP_FLAG_SYN, TCP_FLAG_PSH, TCP_FLAG_URG, TCP_FLAG_ACK


@dataclass
class Alert:
    """A single anomaly finding, emitted by a detector."""
    severity: str         # "low" | "medium" | "high"
    category: str         # e.g. "stealth_scan"
    message: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None


class Detector(ABC):
    """Common interface every detection strategy must implement."""

    name: str = "unnamed_detector"

    @abstractmethod
    def inspect(self, packet: PacketInfo) -> Optional[Alert]:
        """
        Examine one packet. Return an Alert if it's anomalous, else None.

        Stateless detectors (like StealthScanDetector) just look at the
        packet itself. Stateful detectors (port-scan, traffic-spike) will
        update internal tracking structures here too — the interface
        doesn't change either way.
        """
        raise NotImplementedError


class StealthScanDetector(Detector):
    """
    Flags TCP packets with flag combinations that essentially never occur
    in legitimate traffic but are characteristic of well-known stealth
    scan techniques (the kind Nmap implements):

      - NULL scan:  no flags set at all
      - FIN scan:   only FIN set, no ACK/SYN
      - XMAS scan:  FIN + PSH + URG set together
      - SYN+FIN:    mutually contradictory flags set simultaneously
                    (opening and closing a connection at once — never
                    legitimate, a classic firewall/IDS evasion attempt)

    This detector is intentionally stateless — each packet is judged
    entirely on its own header, no history required. That makes it the
    cheapest possible way to validate the full pipeline end-to-end
    before adding anything stateful.
    """

    name = "stealth_scan"

    def inspect(self, packet: PacketInfo) -> Optional[Alert]:
        if packet.tcp is None or packet.ip is None:
            return None

        flags = packet.tcp.flags
        flag_str = packet.tcp.flag_str()

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
        return Alert(
            severity="medium",
            category=self.name,
            message=f"{reason} from {packet.ip.src_ip} -> "
                     f"{packet.ip.dst_ip}:{packet.tcp.dst_port} (flags={flag_str})",
            src_ip=packet.ip.src_ip,
            dst_ip=packet.ip.dst_ip,
            dst_port=packet.tcp.dst_port,
        )


# ---------------------------------------------------------------------------
# Time-bucketed sliding window state (shared by PortScanDetector)
# ---------------------------------------------------------------------------
#
# The naive approach — storing every (ip, port, timestamp) tuple and scanning
# them on each packet — has O(n) lookup cost and unbounded memory growth.
#
# Instead we use fixed-width time buckets. Time is divided into epochs of
# BUCKET_SECONDS width. For each source IP and each epoch, we maintain a set
# of (dst_ip, dst_port) pairs seen. To count unique targets in the window,
# we union the sets across the last WINDOW_SECONDS / BUCKET_SECONDS buckets.
#
# This gives:
#   - O(1) per-packet update (just add to the current bucket's set)
#   - O(B) window query (union B bucket-sets, where B = window/bucket, a
#     small constant — e.g., 6 buckets for a 60s window with 10s buckets)
#   - Automatic expiry: buckets older than the window are never touched again
#     and get swept out of memory during periodic cleanup
#
# This is the same bucketing strategy used by Snort's sfportscan module and
# Zeek's scan detection framework.

BUCKET_SECONDS = 10       # width of each time bucket
SWEEP_INTERVAL = 30       # how often (seconds) we evict expired bucket keys


@dataclass
class _BucketState:
    """
    Per-source-IP state for the sliding window.

    vertical:   { bucket_id: set of (dst_ip, dst_port) } — tracks how many
                distinct (host, port) combinations a source has contacted.
                A vertical scan concentrates on one dst_ip; a horizontal scan
                spreads across many. We store both in the same structure and
                distinguish at query time.

    alerted_at: unix timestamp of the last alert fired for this source,
                used to suppress repeated alerts during an ongoing scan.
    """
    vertical: Dict[int, Set[Tuple[str, int]]] = field(default_factory=dict)
    alerted_at: float = 0.0


class PortScanDetector(Detector):
    """
    Detects two classical port-scan patterns by tracking per-source-IP
    activity within a sliding time window:

    VERTICAL SCAN  — one source contacts many distinct ports on a single
                     destination host. Classic Nmap-style host enumeration.
                     Threshold: port_threshold distinct dst_ports on any
                     single dst_ip within window_seconds.

    HORIZONTAL SCAN — one source contacts the same port across many distinct
                      destination hosts. Characteristic of worms and botnets
                      probing for a specific vulnerable service (e.g. SSH,
                      SMB, RDP) across a subnet.
                      Threshold: host_threshold distinct dst_ips on any
                      single dst_port within window_seconds.

    Default thresholds are modelled on Snort's portscan preprocessor
    documentation and Zeek's Scan::* policy defaults (conservative enough
    to avoid false positives from normal browser or CDN traffic).

    Memory is bounded because bucket keys older than window_seconds are
    swept periodically. The worst-case memory per tracked source IP is
    proportional to the number of unique (dst_ip, dst_port) pairs it
    contacts in one window — for a legitimate host, a small constant.

    Args:
        window_seconds:  length of the sliding detection window (default 60s)
        port_threshold:  distinct dst_ports on one host to trigger vertical
                         alert (default 15, per Snort defaults)
        host_threshold:  distinct dst_ips on one port to trigger horizontal
                         alert (default 20, per Zeek Scan:: defaults)
        cooldown_seconds: minimum seconds between repeated alerts for the
                          same source IP, to suppress alert storms during an
                          ongoing scan (default 30s)
    """

    name = "port_scan"

    def __init__(
        self,
        window_seconds: int = 60,
        port_threshold: int = 15,
        host_threshold: int = 20,
        cooldown_seconds: int = 30,
    ) -> None:
        self.window_seconds = window_seconds
        self.port_threshold = port_threshold
        self.host_threshold = host_threshold
        self.cooldown_seconds = cooldown_seconds

        # src_ip -> _BucketState
        self._state: Dict[str, _BucketState] = defaultdict(_BucketState)
        self._last_sweep: float = time.time()

    # ------------------------------------------------------------------
    # Public interface (Detector ABC)
    # ------------------------------------------------------------------

    def inspect(self, packet: PacketInfo) -> Optional[Alert]:
        # We only care about TCP SYN packets — that's a connection attempt.
        # Tracking all TCP traffic would flood state with ACKs, data segments,
        # and retransmits that carry no scan signal.
        if packet.ip is None or packet.tcp is None:
            return None
        if not (packet.tcp.flags & TCP_FLAG_SYN) or (packet.tcp.flags & TCP_FLAG_ACK):
            return None

        src_ip = packet.ip.src_ip
        dst_ip = packet.ip.dst_ip
        dst_port = packet.tcp.dst_port
        now = packet.timestamp

        self._record(src_ip, dst_ip, dst_port, now)
        self._maybe_sweep(now)

        return self._check(src_ip, now)

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    def _bucket_id(self, ts: float) -> int:
        """Map a unix timestamp to an integer bucket index."""
        return int(ts // BUCKET_SECONDS)

    def _record(self, src_ip: str, dst_ip: str, dst_port: int, now: float) -> None:
        """Add this (dst_ip, dst_port) pair to the current bucket for src_ip."""
        state = self._state[src_ip]
        bucket = self._bucket_id(now)
        if bucket not in state.vertical:
            state.vertical[bucket] = set()
        state.vertical[bucket].add((dst_ip, dst_port))

    def _window_contacts(self, src_ip: str, now: float) -> Set[Tuple[str, int]]:
        """
        Union all (dst_ip, dst_port) pairs across buckets that fall within
        the sliding window. Buckets outside the window are ignored (not yet
        evicted, just not counted — eviction happens in _sweep).
        """
        state = self._state[src_ip]
        oldest_valid_bucket = self._bucket_id(now - self.window_seconds)
        result: Set[Tuple[str, int]] = set()
        for bucket_id, contacts in state.vertical.items():
            if bucket_id >= oldest_valid_bucket:
                result |= contacts
        return result

    def _check(self, src_ip: str, now: float) -> Optional[Alert]:
        """
        Given the current window's contacts for src_ip, check whether either
        scan threshold is exceeded. Suppressed if a recent alert was already
        fired for this source (cooldown).
        """
        state = self._state[src_ip]

        # Cooldown suppression — don't re-alert for an ongoing scan every packet
        if now - state.alerted_at < self.cooldown_seconds:
            return None

        contacts = self._window_contacts(src_ip, now)

        # --- Vertical scan check ---
        # Group by dst_ip, count distinct dst_ports per destination host.
        ports_per_host: Dict[str, Set[int]] = defaultdict(set)
        for dst_ip, dst_port in contacts:
            ports_per_host[dst_ip].add(dst_port)

        for dst_ip, ports in ports_per_host.items():
            if len(ports) >= self.port_threshold:
                state.alerted_at = now
                return Alert(
                    severity="high",
                    category=self.name,
                    message=(
                        f"Vertical port scan: {src_ip} contacted {len(ports)} distinct "
                        f"ports on {dst_ip} within {self.window_seconds}s "
                        f"(threshold={self.port_threshold})"
                    ),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                )

        # --- Horizontal scan check ---
        # Group by dst_port, count distinct dst_ips per port.
        hosts_per_port: Dict[int, Set[str]] = defaultdict(set)
        for dst_ip, dst_port in contacts:
            hosts_per_port[dst_port].add(dst_ip)

        for dst_port, hosts in hosts_per_port.items():
            if len(hosts) >= self.host_threshold:
                state.alerted_at = now
                return Alert(
                    severity="high",
                    category=self.name,
                    message=(
                        f"Horizontal port scan: {src_ip} contacted port {dst_port} "
                        f"on {len(hosts)} distinct hosts within {self.window_seconds}s "
                        f"(threshold={self.host_threshold})"
                    ),
                    src_ip=src_ip,
                    dst_ip=None,
                    dst_port=dst_port,
                )

        return None

    # ------------------------------------------------------------------
    # Memory management
    # ------------------------------------------------------------------

    def _maybe_sweep(self, now: float) -> None:
        """
        Periodically evict expired bucket entries to keep memory bounded.
        Only runs every SWEEP_INTERVAL seconds, not on every packet, so the
        amortized cost per packet is negligible.
        """
        if now - self._last_sweep < SWEEP_INTERVAL:
            return
        self._last_sweep = now
        oldest_valid = self._bucket_id(now - self.window_seconds)

        dead_sources = []
        for src_ip, state in self._state.items():
            state.vertical = {
                b: contacts
                for b, contacts in state.vertical.items()
                if b >= oldest_valid
            }
            # If no buckets remain and no recent alert, drop the source entirely
            if not state.vertical and state.alerted_at < now - self.window_seconds:
                dead_sources.append(src_ip)

        for src_ip in dead_sources:
            del self._state[src_ip]


# ---------------------------------------------------------------------------
# EWMA state (used by TrafficSpikeDetector)
# ---------------------------------------------------------------------------
#
# Exponentially Weighted Moving Average — the same algorithm TCP uses
# internally for round-trip time estimation (RFC 6298, section 2).
#
# On each measurement tick we observe a packet rate R (packets per second).
# The baseline B updates as:
#
#     B  ←  α × R  +  (1 - α) × B
#
# α = 0.125 (1/8) is the RFC 6298 value. It means the baseline adapts
# slowly — a single burst moves B by only 12.5% — so transient spikes
# don't immediately pollute the baseline. We alert when:
#
#     R  >  B × spike_multiplier
#
# i.e., the current rate exceeds the rolling average by some factor.
# spike_multiplier=3.0 ("3× normal") is the conventional starting point
# used by Zeek's PacketFilter and Cisco's IDS documentation.
#
# Warmup guard: EWMA baselines are meaningless until they have seen
# enough samples to stabilize. We skip alerting for the first
# min_samples ticks (default 5 = 5 seconds at 1-second resolution).

EWMA_ALPHA = 0.125          # RFC 6298 smoothing factor
MEASURE_INTERVAL = 1.0      # flush rate counters every N seconds


@dataclass
class _EWMAState:
    baseline: float = 0.0       # current smoothed packets-per-second estimate
    current_count: int = 0      # packets seen in the current interval
    interval_start: float = 0.0 # when the current interval began
    samples_seen: int = 0       # number of completed measurement ticks
    alerted_at: float = 0.0     # last alert timestamp (for cooldown)


class TrafficSpikeDetector(Detector):
    """
    Detects abnormal packet-rate surges using an Exponentially Weighted
    Moving Average (EWMA) adaptive baseline — the same algorithm TCP uses
    for RTT estimation (RFC 6298).

    Two independent trackers run in parallel:

    PER-SOURCE  — each source IP maintains its own EWMA baseline. Flags a
                  single host that suddenly generates far more traffic than
                  its own historical average (e.g. a host beginning to DDoS
                  or exfiltrate data at high rate).

    GLOBAL      — one EWMA across ALL traffic on the interface. Flags a
                  network-wide surge (e.g. a broadcast storm, a large-scale
                  coordinated flood, or sudden mass activity that no single
                  source would trigger alone).

    Why EWMA over a static threshold:
      Static thresholds require manual tuning per environment and produce
      false positives on bursty-but-normal traffic (video calls, backups,
      large file transfers). EWMA adapts to the actual traffic pattern of
      the network the tool is running on, making it self-calibrating across
      different deployment environments — exactly what production IDS tools
      like Zeek and Suricata implement.

    Default parameters:
      alpha=0.125        — RFC 6298 smoothing factor; slow adaptation
                           resists being fooled by sustained floods
      spike_multiplier=3.0 — alert when rate exceeds 3× baseline;
                             consistent with Zeek PacketFilter defaults
      min_samples=5      — require 5 seconds of observation before alerting;
                           prevents false positives during startup
      cooldown_seconds=30 — suppress repeated alerts per source

    Args:
        alpha:             EWMA smoothing factor (0 < α < 1)
        spike_multiplier:  alert when rate > baseline × this value
        min_samples:       warmup ticks before alerting begins
        cooldown_seconds:  minimum gap between repeated alerts per source
        per_source:        whether to track individual source IPs
        global_track:      whether to track aggregate interface traffic
    """

    name = "traffic_spike"

    def __init__(
        self,
        alpha: float = EWMA_ALPHA,
        spike_multiplier: float = 3.0,
        min_samples: int = 5,
        cooldown_seconds: float = 30.0,
        per_source: bool = True,
        global_track: bool = True,
    ) -> None:
        self.alpha = alpha
        self.spike_multiplier = spike_multiplier
        self.min_samples = min_samples
        self.cooldown_seconds = cooldown_seconds
        self.per_source = per_source
        self.global_track = global_track

        # src_ip -> _EWMAState
        self._source_state: Dict[str, _EWMAState] = defaultdict(_EWMAState)
        # Single global tracker
        self._global_state = _EWMAState()

    # ------------------------------------------------------------------
    # Public interface (Detector ABC)
    # ------------------------------------------------------------------

    def inspect(self, packet: PacketInfo) -> Optional[Alert]:
        now = packet.timestamp
        src_ip = packet.ip.src_ip if packet.ip else None

        # --- Global tracker ---
        if self.global_track:
            alert = self._tick(self._global_state, now, label="global", src_ip=None)
            if alert:
                return alert

        # --- Per-source tracker ---
        if self.per_source and src_ip:
            state = self._source_state[src_ip]
            alert = self._tick(state, now, label="per-source", src_ip=src_ip)
            if alert:
                return alert

        return None

    # ------------------------------------------------------------------
    # EWMA core
    # ------------------------------------------------------------------

    def _tick(
        self,
        state: _EWMAState,
        now: float,
        label: str,
        src_ip: Optional[str],
    ) -> Optional[Alert]:
        """
        Increment the packet counter for the current interval. If the interval
        has elapsed, flush: compute the rate, update the EWMA baseline, and
        check whether we should alert. Returns an Alert or None.
        """
        # Initialise interval_start on first packet
        if state.interval_start == 0.0:
            state.interval_start = now

        state.current_count += 1

        elapsed = now - state.interval_start
        if elapsed < MEASURE_INTERVAL:
            return None  # interval not yet complete, nothing to evaluate

        # --- Flush the completed interval ---
        rate = state.current_count / elapsed  # packets per second

        if state.baseline == 0.0:
            # First sample: seed the baseline rather than comparing against zero
            state.baseline = rate
        else:
            state.baseline = self.alpha * rate + (1 - self.alpha) * state.baseline

        state.samples_seen += 1
        state.current_count = 0
        state.interval_start = now

        # Warmup guard: baseline is too noisy until min_samples ticks have passed
        if state.samples_seen < self.min_samples:
            return None

        # Cooldown suppression
        if now - state.alerted_at < self.cooldown_seconds:
            return None

        # Spike check
        threshold = state.baseline * self.spike_multiplier
        if rate > threshold:
            state.alerted_at = now
            return self._make_alert(rate, state.baseline, label, src_ip)

        return None

    def _make_alert(
        self,
        rate: float,
        baseline: float,
        label: str,
        src_ip: Optional[str],
    ) -> Alert:
        if label == "global":
            msg = (
                f"Global traffic spike: {rate:.1f} pkt/s observed vs "
                f"{baseline:.1f} pkt/s baseline "
                f"({rate / baseline:.1f}× normal)"
            )
        else:
            msg = (
                f"Per-source traffic spike from {src_ip}: "
                f"{rate:.1f} pkt/s observed vs {baseline:.1f} pkt/s baseline "
                f"({rate / baseline:.1f}× normal)"
            )
        return Alert(
            severity="high",
            category=self.name,
            message=msg,
            src_ip=src_ip,
        )
