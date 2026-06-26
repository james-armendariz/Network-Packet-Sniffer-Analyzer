"""Command-line entry point for the lightweight packet sniffer."""

import argparse
import sys
import time

from packet_sniffer.pipeline import Pipeline
from packet_sniffer.engine import AnalysisEngine
from packet_sniffer.detectors import StealthScanDetector
from packet_sniffer.alerts import AlertPublisher, ConsoleAlerter


def build_pipeline(iface: str, queue_size: int) -> Pipeline:
    """Construct the capture, parse, and analysis pipeline for a given interface."""
    publisher = AlertPublisher()
    publisher.subscribe(ConsoleAlerter())

    detectors = [StealthScanDetector()]
    engine = AnalysisEngine(detectors=detectors, publisher=publisher)
    return Pipeline(iface=iface, engine=engine, queue_size=queue_size)


def main() -> None:
    """Parse CLI arguments and run the sniffer until interrupted or timed out."""
    parser = argparse.ArgumentParser(description="Lightweight packet sniffer and anomaly analyzer")
    parser.add_argument("--iface", default="lo", help="Network interface to capture on (default: lo)")
    parser.add_argument("--queue-size", type=int, default=1000, help="Max queued packets before drop-oldest kicks in")
    parser.add_argument("--duration", type=float, default=None, help="Stop after N seconds (default: run until Ctrl+C)")
    args = parser.parse_args()

    pipeline = build_pipeline(args.iface, args.queue_size)

    print(f"[*] Capturing on '{args.iface}' (Ctrl+C to stop)...", file=sys.stderr)
    try:
        pipeline.start()
    except PermissionError:
        print("[!] Permission denied opening raw socket. Try running with sudo.", file=sys.stderr)
        sys.exit(1)

    start_time = time.time()
    try:
        while True:
            time.sleep(0.5)
            if args.duration is not None and (time.time() - start_time) >= args.duration:
                break
    except KeyboardInterrupt:
        pass
    finally:
        pipeline.stop()
        stats = pipeline.stats()
        print("\n[*] Shutting down. Summary:", file=sys.stderr)
        for k, v in stats.items():
            print(f"  {k}: {v}", file=sys.stderr)


if __name__ == "__main__":
    main()
