#!/usr/bin/env python3
"""
Windows-Bluetooth-Manager.py

Windows GUI companion to the Linux Bluetooth GTK tool.

Feature parity goals:
- List adapters and paired devices
- Export a device's link key to JSON
- Import a device's link key from JSON (requires SYSTEM or PsExec -s)
- Keep a simple, single-window UI similar to the Linux side

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

import binascii
import json
import platform
import sys
import winreg
from dataclasses import dataclass
from typing import Dict, List, Optional
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, TOP, Button, Frame, Label, Listbox, Scrollbar, StringVar, Tk
from tkinter import filedialog, messagebox, ttk

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

class BluetoothManagerGUI:
    def __init__(self):
        require_windows()
        self.root = Tk()
        self.root.title("Windows Bluetooth Key Manager")
        self.adapters: List[AdapterInfo] = []
        self.devices: List[DeviceInfo] = []
        self.adapter_var = StringVar()

        self._build_layout()
        self.refresh_adapters()

    def _build_layout(self):
        top_frame = Frame(self.root)
        top_frame.pack(side=TOP, fill=BOTH, padx=10, pady=10)

        title = Label(
            top_frame,
            text="Export / Import Bluetooth Link Keys (Windows)",
            font=("Segoe UI", 12, "bold"),
        )
        title.pack(side=TOP, anchor="w")

        info = Label(
            top_frame,
            text=(
                "Reading usually works as Administrator. Writing requires SYSTEM (e.g., PsExec -s)."
            ),
            wraplength=520,
            justify="left",
            fg="#444",
        )
        info.pack(side=TOP, anchor="w", pady=(2, 8))

        adapter_row = Frame(top_frame)
        adapter_row.pack(side=TOP, fill=BOTH, pady=(0, 8))

        Label(adapter_row, text="Adapter:").pack(side=LEFT)
        self.adapter_combo = ttk.Combobox(adapter_row, textvariable=self.adapter_var, state="readonly")
        self.adapter_combo.pack(side=LEFT, padx=6, fill="x", expand=True)
        self.adapter_combo.bind("<<ComboboxSelected>>", lambda _evt: self.load_devices())

        Button(adapter_row, text="Refresh", command=self.refresh_adapters).pack(side=LEFT, padx=(6, 0))

        devices_frame = Frame(self.root)
        devices_frame.pack(side=TOP, fill=BOTH, expand=True, padx=10)

        Label(devices_frame, text="Paired devices:").pack(side=TOP, anchor="w")
        list_frame = Frame(devices_frame)
        list_frame.pack(side=TOP, fill=BOTH, expand=True)

        scrollbar = Scrollbar(list_frame)
        scrollbar.pack(side=RIGHT, fill="y")

        self.device_list = Listbox(list_frame, height=10, yscrollcommand=scrollbar.set)
        self.device_list.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.config(command=self.device_list.yview)

        button_row = Frame(self.root)
        button_row.pack(side=TOP, fill=BOTH, padx=10, pady=8)
        Button(button_row, text="Export to JSON", command=self.export_key).pack(side=LEFT)
        Button(button_row, text="Import from JSON", command=self.import_key).pack(side=LEFT, padx=(8, 0))

        self.status = Label(
            self.root,
            text="Select an adapter to begin.",
            anchor="w",
            justify="left",
            fg="#555",
        )
        self.status.pack(side=TOP, fill=BOTH, padx=10, pady=(0, 10))

    def refresh_adapters(self):
        self.adapters = list_adapters()
        if not self.adapters:
            self.adapter_combo["values"] = []
            self.adapter_var.set("")
            self.set_status(
                "No adapters found. Run as Administrator and ensure Bluetooth is enabled.", error=True
            )
            return

        values = [f"{a.mac} ({a.registry_path})" for a in self.adapters]
        self.adapter_combo["values"] = values
        self.adapter_var.set(values[0])
        self.set_status("Adapters loaded. Select a device to export/import.")
        self.load_devices()

    def current_adapter(self) -> Optional[AdapterInfo]:
        selection = self.adapter_var.get()
        if not selection or not self.adapters:
            return None
        mac = selection.split()[0]
        for adapter in self.adapters:
            if adapter.mac == mac:
                return adapter
        return None

    def load_devices(self):
        adapter = self.current_adapter()
        self.device_list.delete(0, END)
        if adapter is None:
            self.devices = []
            self.set_status("Select an adapter first.", error=True)
            return

        self.devices = list_devices(adapter)
        if not self.devices:
            self.set_status("No paired devices for this adapter.", error=True)
            return

        for dev in self.devices:
            self.device_list.insert(END, f"{dev.name} ({dev.mac})")
        self.set_status("Select a device to export or import a link key.")

    def selected_device(self) -> Optional[DeviceInfo]:
        if not self.devices:
            return None
        selection = self.device_list.curselection()
        if not selection:
            return None
        return self.devices[selection[0]]

    def export_key(self):
        adapter = self.current_adapter()
        device = self.selected_device()
        if adapter is None:
            self.set_status("Select an adapter before exporting.", error=True)
            return
        if device is None:
            self.set_status("Select a device before exporting.", error=True)
            return

        try:
            record = read_link_key(adapter.mac, device.mac)
        except Exception as exc:  # noqa: BLE001
            self.set_status(str(exc), error=True)
            messagebox.showerror("Export failed", str(exc))
            return

        default_name = f"bt-key-{device.mac.replace(':', '-')}.json"
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=default_name,
        )
        if not path:
            return

        with open(path, "w", encoding="utf-8") as f:
            json.dump(record.to_dict(), f, indent=2)
        self.set_status(f"Exported link key for {device.mac} to {Path(path).name}.")
        messagebox.showinfo("Export complete", f"Saved link key to {path}")

    def import_key(self):
        adapter = self.current_adapter()
        device = self.selected_device()
        if adapter is None:
            self.set_status("Select an adapter before importing.", error=True)
            return
        if device is None:
            self.set_status("Select a device before importing.", error=True)
            return

        path = filedialog.askopenfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            loaded = BtKeyRecord.from_dict(data)
            record = BtKeyRecord(adapter.mac, device.mac, loaded.key_hex)
            write_link_key(record)
        except Exception as exc:  # noqa: BLE001
            self.set_status(str(exc), error=True)
            messagebox.showerror("Import failed", str(exc))
            return

        self.set_status(
            f"Imported link key for {device.mac}. Writing requires SYSTEM privileges.",
        )
        messagebox.showinfo(
            "Import complete",
            "Link key imported. If you saw a permission error, rerun as SYSTEM (PsExec -s).",
        )

    def set_status(self, message: str, error: bool = False):
        self.status.config(text=message, fg="#b00020" if error else "#555")

    def run(self):
        self.root.mainloop()


def main():
    app = BluetoothManagerGUI()
    app.run()


if __name__ == "__main__":
    main()
