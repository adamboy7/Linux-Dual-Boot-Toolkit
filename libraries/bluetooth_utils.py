"""Shared Bluetooth utility helpers for Windows and Linux GUIs.

This module centralizes cross-platform helpers plus the Linux service layer
responsible for discovering adapters/devices and handling BlueZ key import,
export, and backup flows. Consolidating the logic here keeps the Linux GUI
lightweight and aligns naming with the Windows helpers.
"""
from __future__ import annotations

import glob
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from .backup_validation import parse_backup_payload, validate_backup_matches

if TYPE_CHECKING:  # Avoid runtime circular imports
    from .bt_gui_logic import BtKeyRecord


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


def reload_bluetooth() -> tuple[bool, str]:
    """Attempt to reload Bluetooth services with platform-aware logic.

    Returns:
        Tuple of ``(success, detail_message)`` summarizing the attempt.
    """

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


# --------------------------- Linux helpers ---------------------------


@dataclass
class AdapterInfo:
    mac: str
    name: str
    is_default: bool
    path: str


@dataclass
class DeviceInfo:
    mac: str
    name: str
    info_path: str


def normalize_mac_colon(mac: str) -> str:
    """Normalize MAC to AA:BB:CC:DD:EE:FF using the shared helper."""

    return normalize_mac(mac, separator=":")


def get_adapters_from_bluetoothctl() -> dict[str, dict[str, object]]:
    """
    Parse ``bluetoothctl list`` to get names and default flag for controllers.

    Returns:
        {
          "AA:BB:CC:DD:EE:FF": {"name": "MyHost", "is_default": True/False},
          ...,
        }
    """

    mapping: dict[str, dict[str, object]] = {}
    try:
        out = subprocess.check_output(
            ["bluetoothctl", "list"], text=True, stderr=subprocess.DEVNULL
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return mapping

    for line in out.splitlines():
        line = line.strip()
        if not line or not line.startswith("Controller "):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        # Controller MAC Name [default]
        mac_raw = parts[1]
        try:
            mac_norm = normalize_mac_colon(mac_raw)
        except ValueError:
            continue

        # Name is everything after the MAC up to any [bracketed] token
        name_tokens = []
        for token in parts[2:]:
            if token.startswith("[") and token.endswith("]"):
                break
            name_tokens.append(token)
        name = " ".join(name_tokens) if name_tokens else mac_norm

        is_default = "[default]" in line

        mapping[mac_norm] = {
            "name": name,
            "is_default": is_default,
        }

    return mapping


def read_key_from_info(info_path: str) -> str:
    """Read ``Key=...`` from a BlueZ info file."""

    with open(info_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip().startswith("Key="):
                return line.strip().split("=", 1)[1].strip()
    raise RuntimeError(f"No 'Key=' entry found in {info_path}")


def export_bt_key(adapter_mac: str, device_mac: str, *, base_dir: str = BASE_DIR):
    from .bt_gui_logic import BtKeyRecord

    adapter_mac = normalize_mac_colon(adapter_mac)
    device_mac = normalize_mac_colon(device_mac)
    info_path = os.path.join(base_dir, adapter_mac, device_mac, "info")

    if not os.path.isfile(info_path):
        raise FileNotFoundError(
            f"BlueZ info file not found at {info_path}. "
            "Is the device paired on this Linux install?"
        )

    key_hex = read_key_from_info(info_path).upper()
    return BtKeyRecord(adapter_mac=adapter_mac, device_mac=device_mac, key_hex=key_hex)


def import_bt_key(record: "BtKeyRecord", *, base_dir: str = BASE_DIR) -> str:
    adapter_mac = normalize_mac_colon(record.adapter_mac)
    device_mac = normalize_mac_colon(record.device_mac)
    info_path = os.path.join(base_dir, adapter_mac, device_mac, "info")

    if not os.path.isfile(info_path):
        raise FileNotFoundError(
            f"BlueZ info file not found at {info_path}. "
            "Make sure the device is paired once in Linux so this file exists."
        )

    # Backup first
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = f"{info_path}.{timestamp}.bak"
    shutil.copy2(info_path, backup_path)

    metadata = {
        "adapter_mac": adapter_mac,
        "device_mac": device_mac,
        "source_info_path": info_path,
        "backup_path": backup_path,
        "created_at": timestamp,
    }

    try:
        with open(f"{info_path}.{timestamp}.json", "w", encoding="utf-8") as meta_file:
            json.dump(metadata, meta_file, indent=2)
    except Exception:  # noqa: BLE001
        pass

    # Read all lines and replace/insert Key=...
    with open(info_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    replaced = False
    for line in lines:
        if line.strip().startswith("Key=") and not replaced:
            new_lines.append(f"Key={record.key_hex}\n")
            replaced = True
        else:
            new_lines.append(line)

    if not replaced:
        # Insert into [LinkKey] section if present; else append
        output_lines = []
        inserted = False
        in_linkkey = False
        for line in new_lines:
            stripped = line.strip()
            output_lines.append(line)
            if stripped == "[LinkKey]":
                in_linkkey = True
            elif stripped.startswith("[") and stripped.endswith("]") and in_linkkey:
                # Leaving [LinkKey]; insert before this section
                output_lines.insert(len(output_lines) - 1, f"Key={record.key_hex}\n")
                inserted = True
                in_linkkey = False

        if not inserted:
            output_lines.append("\n[LinkKey]\n")
            output_lines.append(f"Key={record.key_hex}\n")

        new_lines = output_lines

    temp_path = None
    try:
        fd, temp_path = tempfile.mkstemp(
            prefix="info.", suffix=".tmp", dir=os.path.dirname(info_path)
        )
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
            tmp_file.writelines(new_lines)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())

        os.replace(temp_path, info_path)
    except Exception as exc:  # noqa: BLE001
        try:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
        finally:
            try:
                shutil.copy2(backup_path, info_path)
            except Exception:  # noqa: BLE001
                pass
        raise RuntimeError(f"Failed to update BlueZ info file: {exc}") from exc

    return backup_path


def list_backups(info_path: str) -> list[str]:
    """Return available backup files for a BlueZ info file, newest first."""

    directory = os.path.dirname(info_path) or "."
    basename = os.path.basename(info_path)

    timestamped = glob.glob(os.path.join(directory, f"{basename}.*.bak"))
    legacy = os.path.join(directory, f"{basename}.bak")

    backup_files: set[str] = set(timestamped)
    if os.path.isfile(legacy):
        backup_files.add(legacy)

    return sorted(backup_files, key=lambda p: os.path.getmtime(p), reverse=True)


def restore_backup(info_path: str, backup_path: str):
    payload = parse_backup_payload(backup_path)
    if payload:
        validate_backup_matches(payload, expected_adapter=None, expected_device=None)
    shutil.copy2(backup_path, info_path)


def get_bluetooth_adapters(*, base_dir: str = BASE_DIR) -> list[AdapterInfo]:
    adapters: list[AdapterInfo] = []
    if not os.path.isdir(base_dir):
        return adapters

    btctl_map = get_adapters_from_bluetoothctl()

    for entry in os.listdir(base_dir):
        full_path = os.path.join(base_dir, entry)
        if not os.path.isdir(full_path):
            continue
        if not is_mac_dir_name(entry):
            continue

        mac = normalize_mac_colon(entry)

        # Start with MAC as fallback name
        name = mac
        is_default = False

        # Prefer data from bluetoothctl list (name + [default])
        if mac in btctl_map:
            name = btctl_map[mac]["name"] or mac
            is_default = bool(btctl_map[mac]["is_default"])

        # If bluetoothctl didn't give us a name, try settings file
        if name == mac:
            settings_path = os.path.join(full_path, "settings")
            if os.path.isfile(settings_path):
                try:
                    with open(settings_path, "r", encoding="utf-8") as f:
                        for line in f:
                            if line.startswith("Name="):
                                name_val = line.split("=", 1)[1].strip()
                                if name_val:
                                    name = name_val
                                break
                except Exception:
                    pass

        adapters.append(
            AdapterInfo(mac=mac, name=name, is_default=is_default, path=full_path)
        )

    # If none marked default (e.g. bluetoothctl missing), mark the first one as default
    if adapters and not any(a.is_default for a in adapters):
        adapters[0].is_default = True

    return adapters


# Backwards compatibility
def find_adapters(*, base_dir: str = BASE_DIR) -> list[AdapterInfo]:
    return get_bluetooth_adapters(base_dir=base_dir)


def get_devices_for_adapter(adapter: AdapterInfo) -> list[DeviceInfo]:
    devices: list[DeviceInfo] = []
    if not os.path.isdir(adapter.path):
        return devices

    for entry in os.listdir(adapter.path):
        full_path = os.path.join(adapter.path, entry)
        if not os.path.isdir(full_path):
            continue
        if not is_mac_dir_name(entry):
            continue
        info_path = os.path.join(full_path, "info")
        if not os.path.isfile(info_path):
            continue

        mac = normalize_mac_colon(entry)
        name = mac
        try:
            with open(info_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("Name="):
                        n = line.split("=", 1)[1].strip()
                        if n:
                            name = n
                        break
        except Exception:
            pass

        devices.append(DeviceInfo(mac=mac, name=name, info_path=info_path))

    return devices


__all__ = [
    "AdapterInfo",
    "DeviceInfo",
    "find_adapters",
    "format_mac",
    "get_bluetooth_adapters",
    "get_devices_for_adapter",
    "export_bt_key",
    "import_bt_key",
    "is_mac_dir_name",
    "list_backups",
    "normalize_mac",
    "normalize_mac_colon",
    "reload_bluetooth",
    "restore_backup",
]
