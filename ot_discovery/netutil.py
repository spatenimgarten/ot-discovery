"""Shared network-input parsing for OT Discovery."""

from ipaddress import IPv4Network

DEFAULT_PREFIX = 24


def parse_network(text: str) -> IPv4Network:
    """Parse a user-entered network string, defaulting to /24 if no prefix is given.

    "192.168.1.0" alone is otherwise a /32 (a single, usually non-existent host)
    per ipaddress' own default, which silently turns a scan into a no-op.
    """
    text = text.strip()
    if "/" not in text:
        text = f"{text}/{DEFAULT_PREFIX}"
    return IPv4Network(text, strict=False)
