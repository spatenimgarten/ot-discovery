"""Capture all traffic on a chosen network interface while a vendor
diagnostic tool (PRONETA, IFM LR DEVICE/moneo, Festo Field Device Tool, ...)
reads a device's details, so the protocol can be reverse-engineered from
real bytes afterwards.

This is how the Siemens S7comm SZL reader (ot_discovery/scanners/s7comm.py)
got built: capture PRONETA doing a real "Component Identification" read
against a PLC, then decode the response field-by-field and match it against
what PRONETA displayed. The same approach works for any other vendor's
protocol - we just don't know what protocol a given device actually uses for
it (proprietary UDP, HTTP/REST, Modbus registers, ...) without seeing real
traffic, so this captures everything on the wire instead of assuming.

No command-line arguments needed: just run it, pick the interface from the
list it prints, then open the vendor's tool and read the device out - ideally
note down what the tool *displays* too, so the captured bytes can be matched
against known-good values the same way the Siemens one was verified. Press
Ctrl+C to stop; the capture is saved as it arrives, so nothing is lost even
if the window is closed instead.

The output file is written next to this script (or next to the .exe, if
run as one) as capture_<timestamp>.pcap.
"""

import os
import sys
import time

from scapy.all import AsyncSniffer, PcapWriter, conf
from scapy.arch.windows import get_windows_if_list

conf.verb = 0


def _own_directory() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _choose_interface() -> str:
    interfaces = [i for i in get_windows_if_list() if i.get("ips")]
    print("Available interfaces:")
    for idx, iface in enumerate(interfaces):
        ips = ", ".join(iface["ips"])
        print(f"  [{idx}] {iface['name']} - {ips}")
    while True:
        choice = input("Interface number: ").strip()
        if choice.isdigit() and 0 <= int(choice) < len(interfaces):
            return interfaces[int(choice)]["name"]
        print("Invalid choice, try again.")


def main() -> None:
    iface = _choose_interface()
    output = os.path.join(_own_directory(), f"capture_{time.strftime('%Y%m%d_%H%M%S')}.pcap")

    writer = PcapWriter(output, append=False, sync=True)
    count = 0

    def on_pkt(pkt):
        nonlocal count
        count += 1
        writer.write(pkt)
        if count % 20 == 0:
            print(f"  {count} packets captured so far...")

    print(f"\nSniffing everything on '{iface}' - writing to {output}")
    print("Open the vendor's diagnostic tool now and read out the device's details.")
    print("Press Ctrl+C to stop.\n")

    sniffer = AsyncSniffer(prn=on_pkt, store=False, iface=iface)
    sniffer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        writer.close()

    print(f"\nCaptured {count} frames. Saved to {output}")
    input("Press Enter to close...")


if __name__ == "__main__":
    main()
