"""Command-line interface for OT Discovery."""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from .core import OTScanner, ScanConfig, ScanMode
from .logging_config import setup_logging
from .netutil import parse_network
from .paths import LOG_DIR


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="OT Discovery - Asset Management for Automation Networks")
    parser.add_argument("network", type=str, help="Network to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to use")
    parser.add_argument("--mode", choices=["fast", "deep", "custom"], default="fast", help="Scan mode")
    parser.add_argument("--csv", type=Path, help="Export results to CSV file")
    parser.add_argument("--json", type=Path, help="Export results to JSON file")
    parser.add_argument("--no-arp", action="store_true", help="Skip ARP scan")
    parser.add_argument("--no-dcp", action="store_true", help="Skip DCP scan")
    parser.add_argument("--no-tcp", action="store_true", help="Skip TCP scan")
    parser.add_argument("--udp", action="store_true", help="Enable UDP scan")
    parser.add_argument("--no-plugins", action="store_true", help="Skip plugin identification")
    parser.add_argument("--arp-retries", type=int, default=2,
                         help="ARP attempts per host (default: 2; raise for phones/tablets in sleep mode)")
    parser.add_argument("--tcp-ports", type=str, help="Comma-separated TCP ports to scan")
    parser.add_argument("--udp-ports", type=str, help="Comma-separated UDP ports to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (DEBUG level)")
    parser.add_argument("--log-file", type=Path, default=LOG_DIR / "ot_discovery_cli.log",
                         help="Log file path (default: logs/ot_discovery_cli.log)")
    return parser.parse_args()


async def progress_callback(current: int, total: int, step: str) -> None:
    print(f"\r[{step}] {current}/{total}", end="", flush=True)


async def device_callback(device) -> None:
    print(f"\n  Found: {device.ip} ({device.mac or 'no MAC'})")


async def main() -> int:
    args = parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_file=args.log_file, level=log_level, console_level=log_level)

    try:
        network = parse_network(args.network)
    except ValueError as e:
        print(f"Error: Invalid network: {e}", file=sys.stderr)
        return 1

    config = ScanConfig(
        network=network,
        mode=ScanMode(args.mode),
        interface=args.interface,
        do_arp=not args.no_arp,
        do_dcp=not args.no_dcp,
        do_tcp=not args.no_tcp,
        do_udp=args.udp,
        do_plugins=not args.no_plugins,
        arp_retries=args.arp_retries,
        export_csv=args.csv,
        export_json=args.json,
        progress_callback=progress_callback,
        device_callback=device_callback,
    )

    if args.tcp_ports:
        config.tcp_ports = [int(p.strip()) for p in args.tcp_ports.split(",")]
    if args.udp_ports:
        config.udp_ports = [int(p.strip()) for p in args.udp_ports.split(",")]

    print(f"Starting OT Discovery scan on {network}")
    if args.interface:
        print(f"Using interface: {args.interface}")
    print(f"Mode: {args.mode}")

    scanner = OTScanner(config)
    devices = await scanner.run()

    print(f"\n\nScan complete. Found {len(devices)} device(s).")

    for device in devices:
        print(f"  {device.ip}  {device.mac or '-'}  {device.hostname or '-'}  "
              f"{device.manufacturer or '-'}  {device.device_type.value if device.device_type else '-'}")

    if args.csv:
        print(f"Results exported to CSV: {args.csv}")
    if args.json:
        print(f"Results exported to JSON: {args.json}")

    return 0


def run() -> None:
    """Entry point for console script."""
    sys.exit(asyncio.run(main()))


if __name__ == "__main__":
    run()