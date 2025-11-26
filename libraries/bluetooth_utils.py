"""Shared Bluetooth utility helpers for Windows and Linux GUIs."""
from __future__ import annotations

import re


def normalize_mac(mac: str, separator: str = ":") -> str:
    """Normalize a MAC string to uppercase hex pairs joined by ``separator``.

    Args:
        mac: Input MAC string. May contain separators or whitespace.
        separator: Desired separator between octets (default ':').

    Returns:
        A normalized MAC string such as ``AA:BB:CC:DD:EE:FF``.

    Raises:
        ValueError: If the input cannot be parsed as a 12-hex-digit MAC.
    """

    cleaned = mac.replace(":", "").replace("-", "").strip()
    if len(cleaned) != 12 or not re.fullmatch(r"[0-9A-Fa-f]{12}", cleaned):
        raise ValueError(f"Invalid MAC address: {mac}")

    parts = [cleaned[i : i + 2] for i in range(0, 12, 2)]
    return separator.join(p.upper() for p in parts)


def format_mac(raw_key_name: str, separator: str = ":") -> str:
    """Format a registry-style MAC string (e.g. ``001a7dda710b``) for display."""

    s = raw_key_name.replace(":", "").replace("-", "").strip()
    if len(s) != 12:
        return raw_key_name
    s = s.lower()
    parts = [s[i : i + 2] for i in range(0, 12, 2)]
    return separator.join(p.upper() for p in parts)


def is_mac_dir_name(name: str) -> bool:
    """True if ``name`` looks like a MAC address directory (AA:BB:CC:DD:EE:FF)."""

    return re.fullmatch(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}", name) is not None
