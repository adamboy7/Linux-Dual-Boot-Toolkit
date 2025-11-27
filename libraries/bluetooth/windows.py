from __future__ import annotations

import csv
import io
import platform
import subprocess

from .common import format_mac

WIN_BT_KEYS_REG_PATH = r"SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Keys"
WIN_BT_DEVICES_REG_PATH = r"SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Devices"


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

    def _normalize_mac(value: str) -> str:
        return "".join(ch for ch in value if ch not in ":-").lower()

    def _read_adapter_descriptions() -> dict[str, str]:
        """
        Best-effort lookup for hardware-friendly adapter descriptions via PowerShell.

        Returns a mapping of normalized MAC address -> interface description.
        """

        command = [
            "powershell",
            "-NoLogo",
            "-NoProfile",
            "-Command",
            (
                "Get-NetAdapter -ErrorAction SilentlyContinue | "
                "Where-Object { $_.Name -like '*Bluetooth*' -or "
                "$_.InterfaceDescription -like '*Bluetooth*' } | "
                "Select-Object MacAddress, InterfaceDescription | "
                "ConvertTo-Csv -NoTypeInformation"
            ),
        ]

        try:
            result = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            return {}

        if result.returncode != 0 or not result.stdout:
            return {}

        mapping: dict[str, str] = {}
        reader = csv.DictReader(io.StringIO(result.stdout))
        for row in reader:
            mac = (row.get("MacAddress") or "").strip()
            desc = (row.get("InterfaceDescription") or "").strip()
            if mac and desc:
                mapping[_normalize_mac(mac)] = desc
        return mapping

    adapter_descriptions = _read_adapter_descriptions()

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
                    adapter_name = adapter_descriptions.get(
                        _normalize_mac(subkey_name), ""
                    )

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


__all__ = [
    "WIN_BT_DEVICES_REG_PATH",
    "WIN_BT_KEYS_REG_PATH",
    "decode_bt_name",
    "get_device_display_name",
    "get_windows_bluetooth_adapters",
    "get_windows_devices_for_adapter",
    "read_device_key_hex",
]
