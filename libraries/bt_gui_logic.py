"""Shared Bluetooth GUI logic for cross-platform tools."""
from __future__ import annotations

import json
import os
import platform
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Dict

from .bluetooth_utils import WIN_BT_DEVICES_REG_PATH, WIN_BT_KEYS_REG_PATH, normalize_mac


@dataclass
class BtKeyRecord:
    adapter_mac: str
    device_mac: str
    key_hex: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "adapter_mac": self.adapter_mac,
            "device_mac": self.device_mac,
            "key_hex": self.key_hex,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BtKeyRecord":
        if not isinstance(data, dict):
            raise ValueError("JSON must be an object with adapter_mac, device_mac, and key_hex.")

        required_fields = ["adapter_mac", "device_mac", "key_hex"]
        missing = [f for f in required_fields if f not in data]
        if missing:
            raise ValueError(f"Missing required field(s): {', '.join(missing)}")

        adapter_mac_raw = data["adapter_mac"]
        device_mac_raw = data["device_mac"]
        key_hex = data["key_hex"]

        for name, value in (
            ("adapter_mac", adapter_mac_raw),
            ("device_mac", device_mac_raw),
            ("key_hex", key_hex),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Field '{name}' must be a non-empty string.")

        key_hex_clean = key_hex.strip()
        expected_len = 32  # Link keys are 16 bytes (32 hex chars)
        if len(key_hex_clean) != expected_len:
            raise ValueError(
                f"key_hex must be a {expected_len}-character hex string (got {len(key_hex_clean)} characters)."
            )
        if not all(c in "0123456789abcdefABCDEF" for c in key_hex_clean):
            raise ValueError("key_hex must contain only hexadecimal characters (0-9, A-F).")

        return cls(
            adapter_mac=normalize_mac(adapter_mac_raw),
            device_mac=normalize_mac(device_mac_raw),
            key_hex=key_hex_clean.upper(),
        )


def bt_record_to_json_file(record: BtKeyRecord, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record.to_dict(), f, indent=2)


def bt_record_from_json_file(path: str) -> BtKeyRecord:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return BtKeyRecord.from_dict(data)


def save_timestamped_backup(record: BtKeyRecord, directory: str = ".") -> str:
    """Write a timestamped JSON backup of a Bluetooth key.

    Backups are saved in a consistent ``bt_key_backup_<adapter>_<device>_<timestamp>.json``
    format to the provided directory (defaulting to the current working directory).
    """

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    def _sanitize(mac: str) -> str:
        return mac.replace(":", "").replace("-", "").lower()

    filename = (
        f"bt_key_backup_{_sanitize(record.adapter_mac)}_{_sanitize(record.device_mac)}_{timestamp}.json"
    )
    path = os.path.join(directory or ".", filename)

    payload = record.to_dict() | {"created_at": timestamp}

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return os.path.abspath(path)


# --------------------------- Windows registry helpers ---------------------------


def _require_windows():
    if platform.system() != "Windows":
        raise OSError("This helper is only available on Windows.")


def _reg_export(relative_path: str, destination: str) -> str:
    """Export an HKLM registry subtree to ``destination``."""

    _require_windows()
    abs_dest = os.path.abspath(destination)
    command = ["reg", "export", f"HKLM\\{relative_path}", abs_dest, "/y"]
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise RuntimeError(
            f"Failed to export registry path HKLM\\{relative_path} to {abs_dest}: "
            f"{stderr or result.returncode}"
        )
    return abs_dest


def _reg_import(backup_file: str) -> None:
    """Import a ``.reg`` backup file using the native ``reg`` utility."""

    _require_windows()
    command = ["reg", "import", os.path.abspath(backup_file)]
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise RuntimeError(
            f"Failed to import registry backup {backup_file}: {stderr or result.returncode}"
        )


def backup_windows_bluetooth_registry(directory: str = ".") -> dict[str, str]:
    """Export Bluetooth "Devices" and "Keys" registry trees to ``.reg`` files."""

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backups: dict[str, str] = {}
    for label, reg_path in (
        ("keys", WIN_BT_KEYS_REG_PATH),
        ("devices", WIN_BT_DEVICES_REG_PATH),
    ):
        filename = f"bt_registry_backup_{label}_{timestamp}.reg"
        destination = os.path.join(directory or ".", filename)
        backups[label] = _reg_export(reg_path, destination)
    return backups


def restore_windows_bluetooth_registry(backups: dict[str, str]) -> None:
    """Restore registry backups exported by :func:`backup_windows_bluetooth_registry`."""

    errors: list[str] = []
    for label, path in backups.items():
        try:
            _reg_import(path)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{label}: {exc}")

    if errors:
        raise RuntimeError("; ".join(errors))
