"""Shared Bluetooth utility helpers for Windows and Linux GUIs.

This module centralizes cross-platform helpers plus the Linux service layer
responsible for discovering adapters/devices and handling BlueZ key import,
export, and backup flows. Consolidating the logic here keeps the Linux GUI
lightweight and aligns naming with the Windows helpers.
"""
from __future__ import annotations

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


# --------------------------- Windows helpers ---------------------------


WIN_BT_KEYS_REG_PATH = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Keys"
WIN_BT_DEVICES_REG_PATH = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices"


def _ensure_winreg():
    try:
        import winreg  # type: ignore
    except ModuleNotFoundError as exc:  # pragma: no cover - only on non-Windows
        raise OSError("winreg is only available on Windows.") from exc
    return winreg


def decode_bt_name(raw_value) -> str:
    """Decode Bluetooth name bytes to a human-friendly string.

    Some devices store UTF-16-LE, others store ASCII/UTF-8 bytes. We heuristically
    detect UTF-16; otherwise we treat it as single-byte text.
    """

    if isinstance(raw_value, bytes):
        if not raw_value or all(b == 0 for b in raw_value):
            return ""

        # Heuristic: UTF-16-LE typically has 0x00 in every second byte
        is_even_len = (len(raw_value) % 2 == 0)
        zero_on_odd = sum(
            1 for i in range(1, len(raw_value), 2) if raw_value[i] == 0
        )
        looks_utf16 = is_even_len and zero_on_odd >= len(raw_value) // 4

        if looks_utf16:
            try:
                s = raw_value.decode("utf-16-le", errors="ignore")
            except Exception:
                s = ""
        else:
            try:
                s = raw_value.decode("utf-8", errors="ignore")
            except Exception:
                try:
                    s = raw_value.decode("mbcs", errors="ignore")
                except Exception:
                    s = ""

        return s.rstrip("\x00").strip()

    if isinstance(raw_value, str):
        return raw_value.strip()

    return ""


def get_device_display_name(device_mac_raw: str) -> str:
    """
    Look up a device name under the Bluetooth registry Devices tree.

    Fallback order: ``FriendlyName`` (if non-zero) -> ``Name`` (if non-zero)
    -> formatted MAC.
    """

    winreg = _ensure_winreg()

    key_path = WIN_BT_DEVICES_REG_PATH + "\\" + device_mac_raw
    formatted_mac = format_mac(device_mac_raw)

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as dev_key:
            for value_name in ("FriendlyName", "Name"):
                try:
                    raw_value, _ = winreg.QueryValueEx(dev_key, value_name)
                except FileNotFoundError:
                    continue

                decoded = decode_bt_name(raw_value)
                if decoded:
                    return decoded

    except FileNotFoundError:
        pass
    except PermissionError:
        pass

    return formatted_mac


def get_windows_bluetooth_adapters():
    """Enumerate Bluetooth adapters from the registry (Windows only)."""

    winreg = _ensure_winreg()
    adapters = []

    def _decode_adapter_name(raw_value) -> str:
        name = decode_bt_name(raw_value)
        return name if name else ""

    def _read_global_adapter_name() -> str:
        """Best-effort lookup for a human-friendly adapter name."""

        candidate_paths = [
            r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\General",
            r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\LocalInfo",
        ]
        candidate_values = ["LocalName", "Name", "ComputerName"]

        for path in candidate_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                    for value_name in candidate_values:
                        try:
                            raw_val, _ = winreg.QueryValueEx(key, value_name)
                        except FileNotFoundError:
                            continue
                        decoded = _decode_adapter_name(raw_val)
                        if decoded:
                            return decoded
            except FileNotFoundError:
                continue
            except PermissionError:
                continue

        # Fall back to the computer/host name, which mirrors BlueZ's default
        # controller naming on Linux if registry lookups fail.
        return platform.node()

    global_name = _read_global_adapter_name()

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WIN_BT_KEYS_REG_PATH) as key:
            index = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, index)
                except OSError:
                    break

                # Adapter-specific friendly name if available
                adapter_name = ""
                adapter_key_path = WIN_BT_KEYS_REG_PATH + "\\" + subkey_name
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, adapter_key_path) as adapter_key:
                        for value_name in ("LocalName", "Name", "FriendlyName"):
                            try:
                                raw_val, _ = winreg.QueryValueEx(adapter_key, value_name)
                            except FileNotFoundError:
                                continue
                            adapter_name = _decode_adapter_name(raw_val)
                            if adapter_name:
                                break
                except FileNotFoundError:
                    pass
                except PermissionError:
                    pass

                if not adapter_name:
                    adapter_name = global_name or ""

                formatted_mac = format_mac(subkey_name)
                adapters.append(
                    {
                        "raw": subkey_name,
                        "mac": formatted_mac,
                        "name": adapter_name or formatted_mac,
                    }
                )
                index += 1

    except FileNotFoundError:
        return adapters

    return adapters


def get_windows_devices_for_adapter(adapter_raw: str):
    """Enumerate devices paired to a given adapter (Windows only)."""

    winreg = _ensure_winreg()
    devices = []

    key_path = WIN_BT_KEYS_REG_PATH + "\\" + adapter_raw

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as adap_key:
        index = 0
        while True:
            try:
                value = winreg.EnumValue(adap_key, index)
            except OSError:
                break

            device_mac_raw = value[0]  # value name
            device_name = get_device_display_name(device_mac_raw)
            key_hex = None
            value_data = value[1]
            if isinstance(value_data, bytes):
                key_hex = value_data.hex().upper()

            devices.append(
                {
                    "raw": device_mac_raw,
                    "mac": format_mac(device_mac_raw),
                    "name": device_name,
                    "key_hex": key_hex,
                }
            )

            index += 1

    return devices


def read_device_key_hex(adapter_raw: str, device_raw: str) -> str:
    """Read a device key from the registry and return it as uppercase hex."""

    winreg = _ensure_winreg()
    key_path = WIN_BT_KEYS_REG_PATH + "\\" + adapter_raw

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as adap_key:
        value_data, _ = winreg.QueryValueEx(adap_key, device_raw)

    if not isinstance(value_data, (bytes, bytearray)):
        raise RuntimeError("Unexpected registry data type for the Bluetooth key.")

    return bytes(value_data).hex().upper()


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


def import_bt_key(record: "BtKeyRecord", *, base_dir: str = BASE_DIR) -> str | None:
    from .bt_gui_logic import BtKeyRecord, save_timestamped_backup

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
    info_backup_path = None
    try:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        info_backup_path = f"{info_path}.{timestamp}.bak"
        shutil.copy2(info_path, info_backup_path)

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
                if info_backup_path and os.path.exists(info_backup_path):
                    shutil.copy2(info_backup_path, info_path)
            except Exception:  # noqa: BLE001
                pass
        raise RuntimeError(f"Failed to update BlueZ info file: {exc}") from exc

def get_linux_bluetooth_adapters(*, base_dir: str = BASE_DIR) -> list[AdapterInfo]:
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


# --------------------------- Cross-platform dispatchers ---------------------------


def get_bluetooth_adapters(*, base_dir: str = BASE_DIR):
    """Return Bluetooth adapters using platform-specific discovery."""

    if platform.system() == "Windows":
        return get_windows_bluetooth_adapters()

    return get_linux_bluetooth_adapters(base_dir=base_dir)


def get_devices_for_adapter(adapter):
    """Return devices paired to the given adapter using platform rules."""

    if platform.system() == "Windows":
        raw = adapter
        if isinstance(adapter, dict):
            raw = adapter.get("raw")
        if not isinstance(raw, str):
            raise TypeError("Expected adapter raw string or mapping with 'raw' key")
        return get_windows_devices_for_adapter(raw)

    if not isinstance(adapter, AdapterInfo):
        raise TypeError("Expected AdapterInfo for Linux adapters")

    return get_linux_devices_for_adapter(adapter)


__all__ = [
    "AdapterInfo",
    "DeviceInfo",
    "find_adapters",
    "format_mac",
    "get_bluetooth_adapters",
    "get_linux_bluetooth_adapters",
    "get_linux_devices_for_adapter",
    "get_devices_for_adapter",
    "get_windows_bluetooth_adapters",
    "get_windows_devices_for_adapter",
    "export_bt_key",
    "import_bt_key",
    "is_mac_dir_name",
    "normalize_mac",
    "normalize_mac_colon",
    "reload_bluetooth",
]
