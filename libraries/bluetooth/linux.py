from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from .common import BASE_DIR, is_mac_dir_name, normalize_mac_colon

if TYPE_CHECKING:  # Avoid runtime circular imports
    from ..bt_gui_logic import BtKeyRecord


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
    from ..bt_gui_logic import BtKeyRecord

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


def import_bt_key(
    record: "BtKeyRecord", *, base_dir: str = BASE_DIR
) -> tuple[str | None, str]:
    from ..bt_gui_logic import BtKeyRecord, save_timestamped_backup

    adapter_mac = normalize_mac_colon(record.adapter_mac)
    device_mac = normalize_mac_colon(record.device_mac)
    info_path = os.path.join(base_dir, adapter_mac, device_mac, "info")

    if not os.path.isfile(info_path):
        raise FileNotFoundError(
            f"BlueZ info file not found at {info_path}. "
            "Make sure the device is paired once in Linux so this file exists."
        )

    backup_record: BtKeyRecord | None = None
    try:
        existing_hex = read_key_from_info(info_path).upper()
        backup_record = BtKeyRecord(
            adapter_mac=adapter_mac, device_mac=device_mac, key_hex=existing_hex
        )
    except Exception:  # noqa: BLE001
        backup_record = record

    backup_path: str | None = None
    try:
        backup_path = save_timestamped_backup(backup_record, directory=os.getcwd())
    except Exception:  # noqa: BLE001
        backup_path = None

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    info_backup_path = os.path.join(os.path.dirname(info_path), f"info.{timestamp}.bak")
    try:
        shutil.copy2(info_path, info_backup_path)
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(
            f"Failed to create backup of {info_path} before writing: {e}"
        ) from e

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
            if stripped.startswith("["):
                if in_linkkey and not inserted:
                    output_lines.append(f"Key={record.key_hex}\n")
                    inserted = True
                in_linkkey = stripped.lower() == "[linkkey]"
            output_lines.append(line)
        if not inserted:
            output_lines.append("\n[LinkKey]\n")
            output_lines.append(f"Key={record.key_hex}\n")
        new_lines = output_lines

    try:
        with open(info_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    except Exception as write_err:  # noqa: BLE001
        restore_error: Exception | None = None
        try:
            shutil.copy2(info_backup_path, info_path)
        except Exception as restore_exc:  # noqa: BLE001
            restore_error = restore_exc

        if restore_error is not None:
            raise RuntimeError(
                "Failed to update BlueZ info file and failed to restore from backup. "
                f"Update error: {write_err}; restore error: {restore_error}"
            ) from write_err

        raise RuntimeError(
            "Failed to update BlueZ info file. The original file was restored from "
            f"backup. Update error: {write_err}"
        ) from write_err

    return backup_path, info_backup_path


def get_linux_bluetooth_adapters(*, base_dir: str = BASE_DIR) -> list[AdapterInfo]:
    adapters: list[AdapterInfo] = []

    btctl_map = get_adapters_from_bluetoothctl()

    if not os.path.isdir(base_dir):
        return adapters

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
    return get_linux_bluetooth_adapters(base_dir=base_dir)


def get_linux_devices_for_adapter(adapter: AdapterInfo) -> list[DeviceInfo]:
    devices: list[DeviceInfo] = []
    if not os.path.isdir(adapter.path):
        return devices

    for entry in os.listdir(adapter.path):
        full_path = os.path.join(adapter.path, entry)
        if not os.path.isdir(full_path):
            continue
        if not is_mac_dir_name(entry):
            continue
        if not os.path.isfile(os.path.join(full_path, "info")):
            continue

        mac = normalize_mac_colon(entry)
        name = mac
        info_path = os.path.join(full_path, "info")
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
    "export_bt_key",
    "find_adapters",
    "get_adapters_from_bluetoothctl",
    "get_linux_bluetooth_adapters",
    "get_linux_devices_for_adapter",
    "import_bt_key",
    "read_key_from_info",
]
