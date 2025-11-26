"""Shared Bluetooth GUI logic for cross-platform tools."""
from __future__ import annotations

import glob
import json
import os
from dataclasses import dataclass
from typing import Dict, Iterable, Sequence

from .bluetooth_utils import normalize_mac


class BackupSearchManager:
    """Track and locate Bluetooth backup files across directories.

    This helper centralizes the backup search logic used by GUI frontends so
    they can remain focused on presentation concerns.
    """

    def __init__(self, initial_dirs: Sequence[str] | None = None):
        self.search_dirs: list[str] = []
        if initial_dirs:
            for directory in initial_dirs:
                self.add_directory(directory)
        else:
            self.add_directory(".")

    def add_directory(self, directory: str) -> None:
        normalized = os.path.abspath(directory or ".")
        if normalized not in self.search_dirs:
            self.search_dirs.append(normalized)

    def note_file_location(self, filepath: str) -> None:
        self.add_directory(os.path.dirname(filepath) or ".")

    def find_backup_files(
        self, patterns: Iterable[str] | None = None, include_bak: bool = True
    ) -> list[str]:
        search_patterns = list(patterns or [])
        if not search_patterns:
            search_patterns.extend(["bt_key_backup_*.json"])
            if include_bak:
                search_patterns.append("bt_key_backup_*.bak")

        found: list[str] = []
        seen: set[str] = set()

        for directory in self.search_dirs:
            for pattern in search_patterns:
                pattern_path = os.path.join(directory, pattern)
                for path in glob.glob(pattern_path):
                    if path not in seen:
                        seen.add(path)
                        found.append(path)

        return sorted(found, key=os.path.getmtime, reverse=True)


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
