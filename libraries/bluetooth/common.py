from __future__ import annotations

import platform
import re
import subprocess
from typing import Tuple


BASE_DIR = "/var/lib/bluetooth"


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


def normalize_mac_colon(mac: str) -> str:
    """Normalize MAC to AA:BB:CC:DD:EE:FF using the shared helper."""

    return normalize_mac(mac, separator=":")


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


def reload_bluetooth() -> Tuple[bool, str]:
    """Attempt to reload Bluetooth services with platform-aware logic."""

    current_platform = platform.system()

    if current_platform == "Linux":
        commands = [
            (["systemctl", "restart", "bluetooth"], "systemctl restart bluetooth"),
            (["service", "bluetooth", "restart"], "service bluetooth restart"),
        ]

        errors: list[str] = []

        for cmd, label in commands:
            try:
                subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                return True, label
            except FileNotFoundError:
                errors.append(f"{label}: command not found")
            except subprocess.CalledProcessError as e:
                stderr = (e.stderr or "").strip()
                errors.append(f"{label}: {stderr or e}")

        return False, "; ".join(errors)

    if current_platform == "Windows":
        commands = [
            (
                ["powershell", "-Command", "Restart-Service -Name bthserv -Force"],
                "Restart-Service bthserv",
            ),
            (["net", "stop", "bthserv"], "net stop bthserv && net start bthserv"),
            (["net", "start", "bthserv"], "net start bthserv"),
        ]

        errors: list[str] = []

        for cmd, label in commands:
            try:
                subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                # If we explicitly stopped the service, start it again.
                if label.startswith("net stop"):
                    subprocess.run(
                        ["net", "start", "bthserv"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                return True, label
            except FileNotFoundError:
                errors.append(f"{label}: command not found")
            except subprocess.CalledProcessError as e:
                stderr = (e.stderr or "").strip()
                errors.append(f"{label}: {stderr or e}")

        return False, "; ".join(errors)

    return False, f"Bluetooth reload unsupported on platform: {current_platform}"


__all__ = [
    "BASE_DIR",
    "format_mac",
    "is_mac_dir_name",
    "normalize_mac",
    "normalize_mac_colon",
    "reload_bluetooth",
]
