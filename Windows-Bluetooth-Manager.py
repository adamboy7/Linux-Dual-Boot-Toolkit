#!/usr/bin/env python3
"""
Windows-Bluetooth-Manager.py

Command-line tool to export and import Bluetooth link keys on Windows.

Feature parity with the Linux GTK tool:
- List adapters and paired devices
- Export a device's link key to JSON
- Import a link key from JSON (requires SYSTEM or PsExec -s)

Notes on permissions:
- Bluetooth link keys live under HKLM\\SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Keys
  which is owned by the SYSTEM account. Reading typically works as an Administrator;
  writing usually requires SYSTEM (e.g., run this tool with PsExec -s or an elevated
  scheduled task).
- Friendly device names are read from Parameters\\Devices\\<MAC>\\Name when available;
  otherwise, the MAC address is used.

JSON format matches the Linux tool:
{
  "adapter_mac": "AA:BB:CC:DD:EE:FF",
  "device_mac": "11:22:33:44:55:66",
  "key_hex": "32_HEX_CHARS"
}
"""

import argparse
import binascii
import platform
import sys
import winreg
from dataclasses import dataclass
from typing import Dict, List, Optional

KEYS_BASE = r"SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Keys"
DEVICES_BASE = r"SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Devices"


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
    def from_dict(cls, data: Dict[str, str]) -> "BtKeyRecord":
        if not isinstance(data, dict):
            raise ValueError("JSON must be an object with adapter_mac, device_mac, and key_hex")

        missing = [k for k in ("adapter_mac", "device_mac", "key_hex") if k not in data]
        if missing:
            raise ValueError(f"Missing required field(s): {', '.join(missing)}")

        adapter_mac = normalize_mac(data["adapter_mac"])
        device_mac = normalize_mac(data["device_mac"])
        key_hex = data["key_hex"].strip().upper()
        if len(key_hex) != 32 or any(c not in "0123456789ABCDEF" for c in key_hex):
            raise ValueError("key_hex must be a 32-character hexadecimal string")

        return cls(adapter_mac=adapter_mac, device_mac=device_mac, key_hex=key_hex)


@dataclass
class AdapterInfo:
    mac: str
    registry_path: str


@dataclass
class DeviceInfo:
    mac: str
    name: str
    registry_path: str


def normalize_mac(mac: str) -> str:
    cleaned = mac.strip().replace("-", "").replace(":", "").upper()
    if len(cleaned) != 12 or any(c not in "0123456789ABCDEF" for c in cleaned):
        raise ValueError(f"Invalid MAC address: {mac}")
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def mac_colon_to_registry(mac: str) -> str:
    return normalize_mac(mac).replace(":", "")


def open_registry_key(root, path: str, access: int):
    return winreg.OpenKey(root, path, 0, access)


def list_adapters() -> List[AdapterInfo]:
    adapters: List[AdapterInfo] = []
    try:
        with open_registry_key(winreg.HKEY_LOCAL_MACHINE, KEYS_BASE, winreg.KEY_READ) as key:
            index = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, index)
                except OSError:
                    break
                index += 1
                try:
                    mac_colon = normalize_mac(subkey_name)
                except ValueError:
                    continue
                adapters.append(
                    AdapterInfo(mac=mac_colon, registry_path=f"{KEYS_BASE}\\{subkey_name}")
                )
    except FileNotFoundError:
        pass
    return adapters


def _read_device_name_from_devices_branch(mac_reg: str) -> Optional[str]:
    try:
        with open_registry_key(winreg.HKEY_LOCAL_MACHINE, f"{DEVICES_BASE}\\{mac_reg}", winreg.KEY_READ) as dev_key:
            try:
                name_raw, value_type = winreg.QueryValueEx(dev_key, "Name")
            except FileNotFoundError:
                return None
            if value_type == winreg.REG_SZ:
                return name_raw
            if value_type == winreg.REG_BINARY:
                try:
                    return name_raw.decode("utf-16le", errors="ignore").strip("\x00")
                except Exception:
                    return None
    except FileNotFoundError:
        return None
    return None


def list_devices(adapter: AdapterInfo) -> List[DeviceInfo]:
    devices: List[DeviceInfo] = []
    try:
        with open_registry_key(winreg.HKEY_LOCAL_MACHINE, adapter.registry_path, winreg.KEY_READ) as key:
            index = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, index)
                except OSError:
                    break
                index += 1
                try:
                    mac_colon = normalize_mac(subkey_name)
                except ValueError:
                    continue
                reg_path = f"{adapter.registry_path}\\{subkey_name}"
                display_name = _read_device_name_from_devices_branch(subkey_name) or mac_colon
                devices.append(DeviceInfo(mac=mac_colon, name=display_name, registry_path=reg_path))
    except FileNotFoundError:
        pass
    return devices


def read_link_key(adapter_mac: str, device_mac: str) -> BtKeyRecord:
    adapter_reg = mac_colon_to_registry(adapter_mac)
    device_reg = mac_colon_to_registry(device_mac)
    path = f"{KEYS_BASE}\\{adapter_reg}\\{device_reg}"
    try:
        with open_registry_key(winreg.HKEY_LOCAL_MACHINE, path, winreg.KEY_READ) as key:
            try:
                data, value_type = winreg.QueryValueEx(key, "")
            except FileNotFoundError:
                raise FileNotFoundError(
                    "Link key value not found. Ensure the device is paired on this Windows install."
                )
            if value_type != winreg.REG_BINARY:
                raise RuntimeError(f"Unexpected registry type for key data: {value_type}")
            key_hex = binascii.hexlify(data).decode("ascii").upper()
            if len(key_hex) != 32:
                raise RuntimeError(
                    f"Unexpected key length ({len(key_hex)} hex chars). Expected 32 for 16-byte link key."
                )
            return BtKeyRecord(
                adapter_mac=normalize_mac(adapter_mac),
                device_mac=normalize_mac(device_mac),
                key_hex=key_hex,
            )
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Registry path not found: {path}. Are you running as Administrator on the correct machine?"
        )


def write_link_key(record: BtKeyRecord):
    adapter_reg = mac_colon_to_registry(record.adapter_mac)
    device_reg = mac_colon_to_registry(record.device_mac)
    path = f"{KEYS_BASE}\\{adapter_reg}\\{device_reg}"
    key_bytes = binascii.unhexlify(record.key_hex)

    try:
        with open_registry_key(
            winreg.HKEY_LOCAL_MACHINE, path, winreg.KEY_SET_VALUE | winreg.KEY_WRITE
        ) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_BINARY, key_bytes)
    except PermissionError:
        raise PermissionError(
            "Writing link keys requires SYSTEM privileges. Run this tool via PsExec -s or equivalent."
        )
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Registry path not found: {path}. Pair the device once on Windows to create it first."
        )


def require_windows():
    if platform.system() != "Windows":
        print("This tool only runs on Windows.")
        sys.exit(1)


def cmd_list_adapters(_: argparse.Namespace):
    adapters = list_adapters()
    if not adapters:
        print("No adapters found. Ensure Bluetooth is enabled and you have Administrator rights.")
        return
    for adapter in adapters:
        print(f"Adapter: {adapter.mac}\tRegistry: {adapter.registry_path}")


def cmd_list_devices(args: argparse.Namespace):
    adapter_mac = args.adapter
    adapter_reg = mac_colon_to_registry(adapter_mac)
    target = None
    for adapter in list_adapters():
        if adapter.mac == normalize_mac(adapter_mac):
            target = adapter
            break
        if adapter.registry_path.endswith(adapter_reg):
            target = adapter
            break
    if target is None:
        print(f"Adapter {adapter_mac} not found under {KEYS_BASE}")
        return

    devices = list_devices(target)
    if not devices:
        print("No paired devices found for this adapter.")
        return
    for dev in devices:
        print(f"Device: {dev.name}\tMAC: {dev.mac}\tRegistry: {dev.registry_path}")


def cmd_export(args: argparse.Namespace):
    record = read_link_key(args.adapter, args.device)
    output_path = args.output
    with open(output_path, "w", encoding="utf-8") as f:
        import json

        json.dump(record.to_dict(), f, indent=2)
    print(f"Exported link key for {record.device_mac} to {output_path}")


def cmd_import(args: argparse.Namespace):
    import json

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)
    record = BtKeyRecord.from_dict(data)
    record.adapter_mac = normalize_mac(args.adapter)
    record.device_mac = normalize_mac(args.device)
    write_link_key(record)
    print(f"Imported link key for {record.device_mac} into registry")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export/import Bluetooth link keys on Windows (requires admin/system privileges)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list-adapters", help="List Bluetooth adapters found in the registry").set_defaults(
        func=cmd_list_adapters
    )

    parser_devices = sub.add_parser(
        "list-devices", help="List paired devices for an adapter (provide MAC with colons)"
    )
    parser_devices.add_argument("adapter", help="Adapter MAC (AA:BB:CC:DD:EE:FF)")
    parser_devices.set_defaults(func=cmd_list_devices)

    parser_export = sub.add_parser("export", help="Export a device's link key to JSON")
    parser_export.add_argument("adapter", help="Adapter MAC (AA:BB:CC:DD:EE:FF)")
    parser_export.add_argument("device", help="Device MAC (11:22:33:44:55:66)")
    parser_export.add_argument(
        "-o", "--output", default="bt_key.json", help="Output JSON file (default: bt_key.json)"
    )
    parser_export.set_defaults(func=cmd_export)

    parser_import = sub.add_parser("import", help="Import link key from JSON into registry")
    parser_import.add_argument("adapter", help="Adapter MAC (AA:BB:CC:DD:EE:FF)")
    parser_import.add_argument("device", help="Device MAC (11:22:33:44:55:66)")
    parser_import.add_argument("-i", "--input", default="bt_key.json", help="Input JSON file")
    parser_import.set_defaults(func=cmd_import)

    return parser


def main(argv: Optional[List[str]] = None):
    require_windows()
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
