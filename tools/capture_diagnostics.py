"""Capture traffic to/from a device while a vendor diagnostic tool (PRONETA,
IFM LR DEVICE/moneo, Festo Field Device Tool, ...) reads its details.

This is how the S7comm SZL reader (ot_discovery/scanners/s7comm.py) got
built: capture PRONETA doing a real "Component Identification" read against
a Siemens PLC, then decode the response field-by-field and match it against
what PRONETA displayed. The same approach works for any other vendor's
protocol - we just don't know what protocol IFM/Festo devices actually use
for it (proprietary UDP, HTTP/REST, Modbus registers, ...) without seeing
real traffic, so this casts as wide a net as possible instead of assuming.

Usage:
    python tools/capture_diagnostics.py <interface> <target_ip> [duration_s] [output.pcap]

Example:
    python tools/capture_diagnostics.py "Ethernet 9" 192.168.1.50 90 ifm_capture.pcap

Then, while it's running, open the vendor's tool and read out the device's
details (order number, firmware, serial number, whatever it shows) - ideally
note down what the tool *displays* too, so the captured bytes can be matched
against known-good values the same way the Siemens one was verified.

Windows interface names come from `python -c "from scapy.arch.windows import
get_windows_if_list; [print(i['name']) for i in get_windows_if_list()]"`.
"""

import sys
import time

from scapy.all import AsyncSniffer, wrpcap, conf

conf.verb = 0


def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    iface = sys.argv[1]
    target_ip = sys.argv[2]
    duration = float(sys.argv[3]) if len(sys.argv) > 3 else 90.0
    output = sys.argv[4] if len(sys.argv) > 4 else f"capture_{target_ip.replace('.', '_')}.pcap"

    packets = []

    def on_pkt(pkt):
        packets.append(pkt)
        data = bytes(pkt)
        eth_type = int.from_bytes(data[12:14], "big") if len(data) >= 14 else None
        print(f"t={time.time():.3f} len={len(data)} eth_type=0x{eth_type:04x}" if eth_type else
              f"t={time.time():.3f} len={len(data)}")

    # Broadest possible net: anything to/from the target (any protocol/port),
    # plus DCP (0x8892) for context, since we don't know ahead of time what
    # the vendor's own protocol looks like.
    bpf_filter = f"host {target_ip} or ether proto 0x8892"
    print(f"Sniffing on '{iface}' for {duration:.0f}s (filter: {bpf_filter})")
    print("Open the vendor's diagnostic tool now and read out the device's details.")
    print(f"Will save to {output}")

    sniffer = AsyncSniffer(filter=bpf_filter, prn=on_pkt, store=True, iface=iface)
    sniffer.start()
    time.sleep(duration)
    sniffer.stop()

    print(f"\nCaptured {len(packets)} frames.")
    if packets:
        wrpcap(output, packets)
        print(f"Saved to {output}")
    else:
        print("Nothing captured - check the interface name and that the target IP is reachable.")


if __name__ == "__main__":
    main()
