"""Shared Bluetooth GUI logic for cross-platform tools."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Dict

from .bluetooth_utils import normalize_mac


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
