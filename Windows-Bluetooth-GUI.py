#!/usr/bin/env python3
"""
Windows-Bluetooth-GUI.py

Tkinter-based GUI to export/import Bluetooth pairing keys on Windows.

Features:
- Enumerate adapters by reading HKLM\\SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Keys
- Enumerate paired devices for the selected adapter (names + MACs)
- Export selected device's link key to JSON
- Import link key from JSON into the registry

Run this tool from an elevated/system context (e.g., `psexec -i -s python Windows-Bluetooth-GUI.py`).
"""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from tkinter import N, S, StringVar, Tk, filedialog, messagebox, ttk


if platform.system() != "Windows":
    print("This GUI tool only supports Windows. Run it on Windows as SYSTEM (psexec -i -s).")
    sys.exit(0)

try:
    import winreg  # type: ignore
except ImportError:  # pragma: no cover - environment specific
    print("winreg is required and only available on Windows.")
    sys.exit(1)


ADAPTER_KEYS_PATH = r"SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Keys"
DEVICE_INFO_PATH = r"SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Devices"


@dataclass
class BtKeyRecord:
    adapter_mac: str  # AA:BB:CC:DD:EE:FF
    device_mac: str  # 11:22:33:44:55:66
    key_hex: str  # 32 hex characters

    def to_dict(self) -> dict:
        return {
            "adapter_mac": self.adapter_mac,
            "device_mac": self.device_mac,
            "key_hex": self.key_hex,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BtKeyRecord":
        if not isinstance(data, dict):
            raise ValueError("JSON must be an object with adapter_mac, device_mac, and key_hex.")

        required = ["adapter_mac", "device_mac", "key_hex"]
        missing = [k for k in required if k not in data]
        if missing:
            raise ValueError(f"Missing required field(s): {', '.join(missing)}")

        adapter_mac = normalize_mac_colon(str(data["adapter_mac"]))
        device_mac = normalize_mac_colon(str(data["device_mac"]))
        key_hex = str(data["key_hex"]).strip().upper()

        if len(key_hex) != 32 or not re.fullmatch(r"[0-9A-F]{32}", key_hex):
            raise ValueError("key_hex must be a 32-character hexadecimal string.")

        return cls(adapter_mac=adapter_mac, device_mac=device_mac, key_hex=key_hex)


@dataclass
class AdapterInfo:
    mac_colon: str
    mac_registry: str
    name: str | None

    @property
    def display_name(self) -> str:
        label = self.name or self.mac_colon
        return f"{label} ({self.mac_colon})" if label != self.mac_colon else self.mac_colon


@dataclass
class DeviceInfo:
    mac_colon: str
    mac_registry: str
    name: str | None
    key_hex: str | None

    @property
    def display_name(self) -> str:
        label = self.name or self.mac_colon
        return f"{label} ({self.mac_colon})" if label != self.mac_colon else self.mac_colon


def normalize_mac_colon(mac: str) -> str:
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(clean) != 12:
        raise ValueError(f"Invalid MAC address: {mac}")
    parts = [clean[i : i + 2] for i in range(0, 12, 2)]
    return ":".join(parts)


def mac_to_registry(mac: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", mac).upper()


def registry_to_mac_colon(mac_reg: str) -> str:
    if len(mac_reg) != 12:
        return mac_reg
    return normalize_mac_colon(mac_reg)


def decode_device_name(raw: bytes | str | None) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw.strip() or None
    for encoding in ("utf-16-le", "utf-8", "latin-1"):
        try:
            decoded = raw.decode(encoding, errors="ignore").replace("\x00", "").strip()
            if decoded:
                return decoded
        except Exception:
            continue
    return None


def enumerate_subkeys(root, path: str) -> list[str]:
    names: list[str] = []
    with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
        index = 0
        while True:
            try:
                names.append(winreg.EnumKey(key, index))
                index += 1
            except OSError:
                break
    return names


def lookup_adapter_name(adapter_reg_mac: str) -> str | None:
    mac_compact = adapter_reg_mac.upper()
    ps_cmd = (
        "Get-PnpDevice -Class Bluetooth | "
        "Select-Object FriendlyName,InstanceId | ConvertTo-Json -Compress"
    )
    try:
        output = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        data = json.loads(output)
    except Exception:
        return None

    entries = data if isinstance(data, list) else [data]
    for entry in entries:
        instance_id = str(entry.get("InstanceId", "")).upper()
        friendly = entry.get("FriendlyName")
        if mac_compact in instance_id.replace(":", "").replace("-", ""):
            return friendly
    for entry in entries:
        friendly = entry.get("FriendlyName")
        if friendly:
            return friendly
    return None


def find_adapters() -> list[AdapterInfo]:
    adapters: list[AdapterInfo] = []
    with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
        try:
            adapter_keys = enumerate_subkeys(hklm, ADAPTER_KEYS_PATH)
        except FileNotFoundError:
            return adapters

    for reg_mac in adapter_keys:
        mac_colon = registry_to_mac_colon(reg_mac)
        name = lookup_adapter_name(reg_mac)
        adapters.append(AdapterInfo(mac_colon=mac_colon, mac_registry=reg_mac, name=name))

    return adapters


def read_device_key(hklm, adapter_reg_mac: str, device_reg_mac: str) -> bytes | None:
    adapter_path = f"{ADAPTER_KEYS_PATH}\\{adapter_reg_mac}"
    try:
        with winreg.OpenKey(hklm, adapter_path + f"\\{device_reg_mac}", 0, winreg.KEY_READ) as key:
            value, value_type = winreg.QueryValueEx(key, "")
            if value_type == winreg.REG_BINARY:
                return value
    except FileNotFoundError:
        return None
    return None


def get_device_name(device_reg_mac: str) -> str | None:
    path = f"{DEVICE_INFO_PATH}\\{device_reg_mac}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, "Name")
            return decode_device_name(value)
    except FileNotFoundError:
        return None


def find_devices(adapter: AdapterInfo) -> list[DeviceInfo]:
    devices: list[DeviceInfo] = []
    with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
        adapter_path = f"{ADAPTER_KEYS_PATH}\\{adapter.mac_registry}"
        try:
            device_keys = enumerate_subkeys(hklm, adapter_path)
        except FileNotFoundError:
            return devices

        for dev_reg in device_keys:
            dev_mac = registry_to_mac_colon(dev_reg)
            key_bytes = read_device_key(hklm, adapter.mac_registry, dev_reg)
            key_hex = key_bytes.hex().upper() if key_bytes else None
            name = get_device_name(dev_reg)
            devices.append(
                DeviceInfo(
                    mac_colon=dev_mac,
                    mac_registry=dev_reg,
                    name=name,
                    key_hex=key_hex,
                )
            )
    return devices


def windows_export_key(adapter: AdapterInfo, device: DeviceInfo) -> BtKeyRecord:
    with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
        key_bytes = read_device_key(hklm, adapter.mac_registry, device.mac_registry)
        if not key_bytes:
            raise FileNotFoundError("Bluetooth key not found in registry.")
    key_hex = key_bytes.hex().upper()
    return BtKeyRecord(adapter_mac=adapter.mac_colon, device_mac=device.mac_colon, key_hex=key_hex)


def write_device_key(record: BtKeyRecord) -> str | None:
    adapter_reg = mac_to_registry(record.adapter_mac)
    device_reg = mac_to_registry(record.device_mac)
    backup_file: str | None = None

    with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
        adapter_path = f"{ADAPTER_KEYS_PATH}\\{adapter_reg}"
        adapter_key = winreg.CreateKeyEx(hklm, adapter_path, 0, winreg.KEY_READ | winreg.KEY_WRITE)
        with adapter_key:
            device_key = winreg.CreateKeyEx(adapter_key, device_reg, 0, winreg.KEY_READ | winreg.KEY_WRITE)
            with device_key:
                try:
                    existing_value, value_type = winreg.QueryValueEx(device_key, "")
                except FileNotFoundError:
                    existing_value, value_type = None, None

                if existing_value is not None and value_type == winreg.REG_BINARY:
                    record_dict = BtKeyRecord(
                        adapter_mac=record.adapter_mac,
                        device_mac=record.device_mac,
                        key_hex=existing_value.hex().upper(),
                    ).to_dict()
                    fd, backup_file = tempfile.mkstemp(prefix="bt-key-backup-", suffix=".json")
                    with os.fdopen(fd, "w", encoding="utf-8") as backup_handle:
                        json.dump(record_dict, backup_handle, indent=2)

                winreg.SetValueEx(device_key, "", 0, winreg.REG_BINARY, bytes.fromhex(record.key_hex))
    return backup_file


def windows_import_key(record: BtKeyRecord) -> str | None:
    return write_device_key(record)


class BtKeyGui(Tk):
    def __init__(self):
        super().__init__()
        self.title("Bluetooth Key Sync (Windows)")
        self.geometry("520x220")
        self.resizable(False, False)

        self.adapters: list[AdapterInfo] = []
        self.devices: list[DeviceInfo] = []

        self.adapter_var = StringVar()
        self.device_var = StringVar()

        self._build_ui()
        self.refresh_adapters()

    def _build_ui(self):
        padding = {"padx": 8, "pady": 4}

        main = ttk.Frame(self)
        main.grid(row=0, column=0, sticky=N + S + "ew")

        ttk.Label(main, text="Adapter:").grid(row=0, column=0, sticky="w", **padding)
        self.adapter_combo = ttk.Combobox(main, textvariable=self.adapter_var, state="readonly", width=45)
        self.adapter_combo.grid(row=0, column=1, sticky="ew", **padding)
        self.adapter_combo.bind("<<ComboboxSelected>>", lambda _event: self.on_adapter_changed())

        ttk.Label(main, text="Device:").grid(row=1, column=0, sticky="w", **padding)
        self.device_combo = ttk.Combobox(main, textvariable=self.device_var, state="readonly", width=45)
        self.device_combo.grid(row=1, column=1, sticky="ew", **padding)

        button_frame = ttk.Frame(main)
        button_frame.grid(row=2, column=0, columnspan=2, sticky="ew", **padding)
        button_frame.columnconfigure((0, 1, 2), weight=1)

        export_btn = ttk.Button(button_frame, text="Export key to JSON…", command=self.on_export)
        export_btn.grid(row=0, column=0, sticky="ew", padx=4)

        import_btn = ttk.Button(button_frame, text="Import key from JSON…", command=self.on_import)
        import_btn.grid(row=0, column=1, sticky="ew", padx=4)

        refresh_btn = ttk.Button(button_frame, text="Refresh", command=self.refresh_adapters)
        refresh_btn.grid(row=0, column=2, sticky="ew", padx=4)

        self.status_var = StringVar()
        status = ttk.Label(main, textvariable=self.status_var, foreground="gray")
        status.grid(row=3, column=0, columnspan=2, sticky="w", **padding)

    def set_status(self, text: str):
        self.status_var.set(text)

    def refresh_adapters(self):
        self.adapters = find_adapters()
        self.adapter_combo["values"] = [a.display_name for a in self.adapters]
        if self.adapters:
            self.adapter_combo.current(0)
            self.on_adapter_changed()
            self.set_status("Adapters refreshed.")
        else:
            self.device_combo["values"] = []
            self.set_status("No Bluetooth adapters found under BTHPORT\\Parameters\\Keys.")

    def on_adapter_changed(self):
        selection = self.adapter_combo.current()
        if selection < 0 or selection >= len(self.adapters):
            return
        adapter = self.adapters[selection]
        self.devices = find_devices(adapter)
        self.device_combo["values"] = [d.display_name for d in self.devices]
        if self.devices:
            self.device_combo.current(0)
            self.set_status(f"Loaded {len(self.devices)} devices for {adapter.mac_colon}.")
        else:
            self.device_combo.set("")
            self.set_status(f"No paired devices found for {adapter.mac_colon}.")

    def _get_selected_adapter(self) -> AdapterInfo | None:
        idx = self.adapter_combo.current()
        if 0 <= idx < len(self.adapters):
            return self.adapters[idx]
        messagebox.showerror("No adapter selected", "Please choose a Bluetooth adapter.")
        return None

    def _get_selected_device(self) -> DeviceInfo | None:
        idx = self.device_combo.current()
        if 0 <= idx < len(self.devices):
            return self.devices[idx]
        messagebox.showerror("No device selected", "Please choose a paired device.")
        return None

    def on_export(self):
        adapter = self._get_selected_adapter()
        device = self._get_selected_device()
        if not adapter or not device:
            return
        try:
            record = windows_export_key(adapter, device)
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))
            return

        default_name = f"bt-key-{adapter.mac_registry}-{device.mac_registry}.json"
        filename = filedialog.asksaveasfilename(
            title="Save Bluetooth key to JSON",
            defaultextension=".json",
            initialfile=default_name,
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not filename:
            return

        with open(filename, "w", encoding="utf-8") as handle:
            json.dump(record.to_dict(), handle, indent=2)
        self.set_status(f"Exported key for {device.display_name} to {filename}.")
        messagebox.showinfo("Export successful", f"Saved key to:\n{filename}")

    def on_import(self):
        adapter = self._get_selected_adapter()
        device = self._get_selected_device()
        if not adapter:
            return
        if not device:
            return

        filename = filedialog.askopenfilename(
            title="Select JSON file with Bluetooth key",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not filename:
            return

        try:
            with open(filename, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            record = BtKeyRecord.from_dict(data)
            record.adapter_mac = adapter.mac_colon
            record.device_mac = device.mac_colon
            backup_path = windows_import_key(record)
        except Exception as exc:
            messagebox.showerror("Import failed", str(exc))
            return

        msg_lines = ["Key imported successfully."]
        if backup_path:
            msg_lines.append(f"Backup of previous key saved to:\n{backup_path}")
        self.set_status("Imported key into registry.")
        messagebox.showinfo("Import successful", "\n\n".join(msg_lines))


if __name__ == "__main__":
    app = BtKeyGui()
    app.mainloop()
