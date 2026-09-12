"""Npcap driver detection (Windows only).

Npcap is a kernel-mode driver, not a Python package - it can't be bundled
into the PyInstaller executable the way scapy/netifaces are (that would
also need Npcap's paid OEM license, since the free edition disallows
redistribution). Without it, ARP scanning falls back to the slower
per-host SendARP API and DCP (Profinet) scanning is skipped.
"""

from __future__ import annotations

import sys

NPCAP_DOWNLOAD_URL = "https://npcap.com/#download"


def is_npcap_installed() -> bool:
    """Check whether the Npcap driver is registered on this machine."""
    if sys.platform != "win32":
        return True
    import winreg

    try:
        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap")
        return True
    except OSError:
        return False
