"""Shared helpers to infer and validate Bluetooth backup targets."""

from __future__ import annotations

import json
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Callable, Iterable, TypedDict

from libraries.bluetooth_utils import is_mac_dir_name, normalize_mac


class ParsedBackupPayload(TypedDict):
    key_path: str
    value_name: str
    reg_type: int
    reg_value: object
    value_format: str
    created_at: str | None
    adapter_mac: str | None
    device_mac: str | None


@dataclass
class BackupParseResult:
    payload: ParsedBackupPayload
    raw: dict


def _normalize_optional(mac: str | None) -> str | None:
    if mac is None:
        return None
    try:
        return normalize_mac(mac, separator=":")
    except ValueError:
        return None


def _path_parts(path: str) -> Iterable[str]:
    # ``Path(path).parts`` preserves drive letters but keeps separator-aware chunks.
    # Split again on both separators to cover Windows paths passed on Linux.
    parts = list(Path(path).parts)
    fallback_parts = re.split(r"[\\/]+", path)
    for part in parts + fallback_parts:
        if part:
            yield part


def _macs_from_path_part(part: str) -> list[str]:
    """Return normalized MACs found within a path segment."""

    macs: list[str] = []

    if is_mac_dir_name(part):
        candidate = _normalize_optional(part)
        if candidate:
            macs.append(candidate)

    macs.extend(
        candidate
        for candidate in (
            _normalize_optional(match) for match in re.findall(r"[0-9A-Fa-f]{12}", part)
        )
        if candidate
    )

    return macs


def extract_macs_from_path(path: str) -> tuple[str | None, str | None]:
    """Best-effort extraction of adapter/device MACs from a file path."""

    macs: list[str] = []
    for part in _path_parts(path):
        macs.extend(_macs_from_path_part(part))

    adapter_mac = macs[-2] if len(macs) >= 2 else None
    device_mac = macs[-1] if macs else None
    return adapter_mac, device_mac


def extract_macs_from_info_content(path: str) -> tuple[str | None, str | None]:
    """Parse an info/backup file for adapter/device hints."""

    adapter_mac = None
    device_mac = None

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                stripped = line.strip()
                if device_mac is None:
                    match_device = re.match(r"^Address=([0-9A-Fa-f:]{17})$", stripped)
                    if match_device:
                        device_mac = _normalize_optional(match_device.group(1))
                if adapter_mac is None:
                    match_adapter = re.match(r"^Adapter=([0-9A-Fa-f:]{17})$", stripped)
                    if match_adapter:
                        adapter_mac = _normalize_optional(match_adapter.group(1))
                if adapter_mac and device_mac:
                    break
    except OSError:
        pass

    return adapter_mac, device_mac


def extract_macs_from_json_metadata(path: str) -> tuple[str | None, str | None]:
    """Extract adapter/device hints from JSON metadata fields."""

    adapter_mac = None
    device_mac = None

    if not path.lower().endswith(".json"):
        return adapter_mac, device_mac

    try:
        with open(path, "r", encoding="utf-8") as meta_file:
            data = json.load(meta_file)
    except Exception:
        return adapter_mac, device_mac

    if isinstance(data, dict):
        adapter_mac = data.get("adapter_mac") or data.get("Adapter")
        device_mac = data.get("device_mac") or data.get("Device")

        # Windows backups store the adapter/device within registry metadata
        if adapter_mac is None:
            key_path = data.get("key_path") or data.get("path")
            if isinstance(key_path, str):
                adapter_mac, _ = extract_macs_from_path(key_path)

        if device_mac is None:
            value_name = data.get("value_name")
            if isinstance(value_name, str):
                device_mac = _normalize_optional(value_name)

        source_path = data.get("source_info_path") or data.get("path")
        if isinstance(source_path, str):
            path_adapter, path_device = extract_macs_from_path(source_path)
            adapter_mac = adapter_mac or path_adapter
            device_mac = device_mac or path_device

    return _normalize_optional(adapter_mac), _normalize_optional(device_mac)


def parse_backup_payload(filepath: str) -> BackupParseResult:
    """Load and validate a Windows backup payload from disk."""

    try:
        with open(filepath, "r", encoding="utf-8") as file:
            data = json.load(file)
    except Exception as exc:
        raise ValueError(f"Unable to read backup file: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Backup file must contain a JSON object.")

    required_fields = ["key_path", "value_name", "value_type", "value_format", "value_data"]
    missing = [field for field in required_fields if field not in data]
    if missing:
        raise ValueError(
            f"Backup file is missing required field(s): {', '.join(sorted(missing))}"
        )

    key_path = data.get("key_path")
    value_name = data.get("value_name")
    value_type = data.get("value_type")
    value_format = data.get("value_format")
    value_data = data.get("value_data")
    created_at = data.get("created_at") if isinstance(data.get("created_at"), str) else None

    if not isinstance(key_path, str) or not key_path.strip():
        raise ValueError("Backup key_path must be a non-empty string.")
    if not isinstance(value_name, str) or not value_name.strip():
        raise ValueError("Backup value_name must be a non-empty string.")

    try:
        reg_type = int(value_type)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Backup value_type must be a valid integer.") from exc

    if value_format == "hex":
        if not isinstance(value_data, str):
            raise ValueError(
                "Backup value_data must be a hexadecimal string when value_format is 'hex'."
            )
        try:
            reg_value = bytes.fromhex(value_data)
        except ValueError as exc:
            raise ValueError(
                "value_data is not valid hexadecimal data and cannot be restored."
            ) from exc
    elif value_format == "literal":
        reg_value = value_data
    else:
        raise ValueError(
            "Unsupported value_format in backup file. Expected 'hex' or 'literal'."
        )

    adapter_mac, device_mac = extract_macs_from_json_metadata(filepath)
    if adapter_mac is None or device_mac is None:
        path_adapter, path_device = extract_macs_from_path(filepath)
        adapter_mac = adapter_mac or path_adapter
        device_mac = device_mac or path_device

    payload: ParsedBackupPayload = {
        "key_path": key_path,
        "value_name": value_name,
        "reg_type": reg_type,
        "reg_value": reg_value,
        "value_format": value_format,
        "created_at": created_at,
        "adapter_mac": _normalize_optional(adapter_mac),
        "device_mac": _normalize_optional(device_mac),
    }

    return BackupParseResult(payload=payload, raw=data)


def validate_backup_matches(
    expected_adapter: str,
    expected_device: str | None,
    backup_path: str,
    error_callback: Callable[[str, str | None], None] | None = None,
    mismatch_title: str | None = "Restore blocked: adapter/device mismatch",
) -> bool:
    """Confirm a backup file appears to belong to the selected adapter/device."""

    expected_adapter_norm = _normalize_optional(expected_adapter)
    expected_device_norm = _normalize_optional(expected_device)

    found_adapter = None
    found_device = None

    json_adapter, json_device = extract_macs_from_json_metadata(backup_path)
    found_adapter = found_adapter or json_adapter
    found_device = found_device or json_device

    if found_adapter is None or found_device is None:
        content_adapter, content_device = extract_macs_from_info_content(backup_path)
        found_adapter = found_adapter or content_adapter
        found_device = found_device or content_device

    path_adapter, path_device = extract_macs_from_path(backup_path)
    found_adapter = found_adapter or path_adapter
    found_device = found_device or path_device

    found_adapter = _normalize_optional(found_adapter)
    found_device = _normalize_optional(found_device)

    mismatches = []
    if found_adapter and expected_adapter_norm and found_adapter != expected_adapter_norm:
        mismatches.append(
            f"Backup adapter {found_adapter} does not match selected {expected_adapter_norm}."
        )
    if found_device and expected_device_norm and found_device != expected_device_norm:
        mismatches.append(
            f"Backup device {found_device} does not match selected {expected_device_norm}."
        )

    if mismatches:
        if error_callback:
            error_callback("\n".join(mismatches), mismatch_title)
        return False

    return True
