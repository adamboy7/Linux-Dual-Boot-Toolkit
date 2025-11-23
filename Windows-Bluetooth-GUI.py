#!/usr/bin/env python3
"""
Windows GUI to export/import Bluetooth pairing keys (dual-boot helper).

This tool mirrors the Linux GTK utility but targets Windows' Bluetooth
stack. It allows exporting a paired device's link key from the Windows
registry to JSON and importing a key from JSON back into the registry.

Typical usage in a dual-boot workflow:
1. Pair a headset in Windows.
2. Run this tool as Administrator and export the device key to JSON.
3. Boot into Linux and import the JSON with the Linux GUI.

And vice versa to bring a Linux key into Windows.

Requirements:
- Run as Administrator to modify registry values.
- Python 3 with Tkinter available (default on CPython Windows installers).
"""

import binascii
import json
import platform
import tkinter as tk
from dataclasses import dataclass
from tkinter import filedialog, messagebox, ttk
from typing import Optional
import winreg

BASE_REG_PATH = r"SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Keys"


@dataclass
class BtKeyRecord:
    adapter_mac: str  # AA:BB:CC:DD:EE:FF
    device_mac: str  # 11:22:33:44:55:66
    key_hex: str

    def to_dict(self) -> dict:
        return {
            "adapter_mac": self.adapter_mac,
            "device_mac": self.device_mac,
            "key_hex": self.key_hex,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BtKeyRecord":
        return cls(
            adapter_mac=data["adapter_mac"],
            device_mac=data["device_mac"],
            key_hex=data["key_hex"],
        )


@dataclass
class AdapterInfo:
    mac: str
    name: str


@dataclass
class DeviceInfo:
    mac: str
    name: str


# ----- helpers -----

def normalize_mac_colon(mac: str) -> str:
    mac = mac.strip().replace("-", ":").upper()
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC address: {mac}")
    return ":".join(f"{int(part, 16):02X}" for part in parts)


def mac_colon_to_hex(mac: str) -> str:
    """Convert AA:BB:CC:DD:EE:FF -> aabbccddeeff (lowercase) for registry paths."""
    return normalize_mac_colon(mac).replace(":", "").lower()


def mac_hex_to_colon(name: str) -> str:
    """Convert aabbccddeeff -> AA:BB:CC:DD:EE:FF."""
    name = name.strip().replace(":", "").replace("-", "")
    if len(name) != 12:
        raise ValueError(f"Not a 12-digit hex MAC: {name}")
    parts = [name[i : i + 2] for i in range(0, 12, 2)]
    return ":".join(part.upper() for part in parts)


def _try_query_default_or_known(subkey) -> Optional[bytes]:
    # First, try the default unnamed value
    try:
        data, _ = winreg.QueryValueEx(subkey, None)
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
    except FileNotFoundError:
        pass

    # Some Windows builds use named values like "LTK" or "LinkKey"
    for candidate in ("LTK", "LinkKey"):
        try:
            data, _ = winreg.QueryValueEx(subkey, candidate)
            if isinstance(data, (bytes, bytearray)):
                return bytes(data)
        except FileNotFoundError:
            continue
    return None


def export_key(adapter_mac: str, device_mac: str) -> BtKeyRecord:
    adapter_hex = mac_colon_to_hex(adapter_mac)
    device_hex = mac_colon_to_hex(device_mac)

    path = f"{BASE_REG_PATH}\\{adapter_hex}\\{device_hex}"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as dev_key:
        data = _try_query_default_or_known(dev_key)
        if data is None:
            raise RuntimeError(
                "No binary key found for the selected device. "
                "Ensure the device is paired in Windows."
            )
    key_hex = binascii.hexlify(data).decode("ascii").upper()
    return BtKeyRecord(
        adapter_mac=normalize_mac_colon(adapter_mac),
        device_mac=normalize_mac_colon(device_mac),
        key_hex=key_hex,
    )


def import_key(record: BtKeyRecord):
    adapter_hex = mac_colon_to_hex(record.adapter_mac)
    device_hex = mac_colon_to_hex(record.device_mac)

    device_path = f"{BASE_REG_PATH}\\{adapter_hex}\\{device_hex}"
    with winreg.CreateKeyEx(
        winreg.HKEY_LOCAL_MACHINE,
        device_path,
        0,
        winreg.KEY_SET_VALUE | winreg.KEY_WRITE,
    ) as dev_key:
        winreg.SetValueEx(
            dev_key,
            None,
            0,
            winreg.REG_BINARY,
            binascii.unhexlify(record.key_hex),
        )


def find_adapters() -> list[AdapterInfo]:
    adapters: list[AdapterInfo] = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, BASE_REG_PATH, 0, winreg.KEY_READ) as base:
            idx = 0
            while True:
                try:
                    name = winreg.EnumKey(base, idx)
                except OSError:
                    break
                idx += 1
                try:
                    mac = mac_hex_to_colon(name)
                except ValueError:
                    continue
                adapters.append(AdapterInfo(mac=mac, name=mac))
    except FileNotFoundError:
        pass
    return adapters


def find_devices(adapter: AdapterInfo) -> list[DeviceInfo]:
    devices: list[DeviceInfo] = []
    adapter_hex = mac_colon_to_hex(adapter.mac)
    path = f"{BASE_REG_PATH}\\{adapter_hex}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as adapter_key:
            idx = 0
            while True:
                try:
                    name = winreg.EnumKey(adapter_key, idx)
                except OSError:
                    break
                idx += 1
                try:
                    mac_colon = mac_hex_to_colon(name)
                except ValueError:
                    continue
                devices.append(DeviceInfo(mac=mac_colon, name=mac_colon))
    except FileNotFoundError:
        pass
    return devices


# ----- GUI -----

class BtKeyGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Bluetooth Key Sync (Windows)")
        self.geometry("520x220")
        self.resizable(False, False)

        self.adapters: list[AdapterInfo] = find_adapters()
        self.devices: list[DeviceInfo] = []

        if not self.adapters:
            messagebox.showerror(
                "No adapters",
                "No Bluetooth adapters found in the registry.\n\n"
                "Ensure Bluetooth is installed and you have paired at least one device.",
            )
            self.destroy()
            return

        main = ttk.Frame(self, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        warn = ttk.Label(
            main,
            text="Run as Administrator to read/write Bluetooth keys.",
            foreground="#b36b00",
        )
        warn.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        ttk.Label(main, text="Adapter:").grid(row=1, column=0, sticky="w")
        self.adapter_var = tk.StringVar()
        self.adapter_combo = ttk.Combobox(main, textvariable=self.adapter_var, state="readonly")
        self.adapter_combo.grid(row=1, column=1, columnspan=2, sticky="ew", pady=4)
        self.adapter_combo.bind("<<ComboboxSelected>>", lambda _event: self._reload_devices())

        ttk.Label(main, text="Device:").grid(row=2, column=0, sticky="w")
        self.device_var = tk.StringVar()
        self.device_combo = ttk.Combobox(main, textvariable=self.device_var, state="readonly")
        self.device_combo.grid(row=2, column=1, columnspan=2, sticky="ew", pady=4)

        self.export_btn = ttk.Button(main, text="Export key to JSON…", command=self.on_export)
        self.export_btn.grid(row=3, column=0, sticky="ew", pady=10)

        self.import_btn = ttk.Button(main, text="Import key from JSON…", command=self.on_import)
        self.import_btn.grid(row=3, column=1, sticky="ew", pady=10)

        self.refresh_btn = ttk.Button(main, text="Refresh devices", command=self._reload_devices)
        self.refresh_btn.grid(row=3, column=2, sticky="ew", pady=10)

        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(main, textvariable=self.status_var)
        status.grid(row=4, column=0, columnspan=3, sticky="w", pady=(6, 0))

        main.columnconfigure(1, weight=1)
        main.columnconfigure(2, weight=1)

        self._populate_adapters()

    # --- helpers ---
    def _populate_adapters(self):
        values = [f"{a.name} ({a.mac})" for a in self.adapters]
        self.adapter_combo["values"] = values
        if values:
            self.adapter_combo.current(0)
        self._reload_devices()

    def _get_selected_adapter(self) -> Optional[AdapterInfo]:
        idx = self.adapter_combo.current()
        if idx < 0:
            return None
        return self.adapters[idx]

    def _get_selected_device(self) -> Optional[DeviceInfo]:
        idx = self.device_combo.current()
        if idx < 0:
            return None
        return self.devices[idx] if idx < len(self.devices) else None

    def _reload_devices(self):
        adapter = self._get_selected_adapter()
        if adapter is None:
            self.status_var.set("No adapter selected")
            self.device_combo["values"] = []
            self.devices = []
            return

        self.devices = find_devices(adapter)
        values = [f"{d.name} ({d.mac})" for d in self.devices]
        self.device_combo["values"] = values
        if values:
            self.device_combo.current(0)
            self.status_var.set(f"Found {len(values)} device(s) for {adapter.mac}")
        else:
            self.device_combo.set("")
            self.status_var.set(f"No devices found for {adapter.mac}")

    # --- actions ---
    def on_export(self):
        adapter = self._get_selected_adapter()
        device = self._get_selected_device()
        if adapter is None or device is None:
            messagebox.showerror("Selection required", "Select an adapter and device first.")
            return

        default_name = f"{device.name}-bt-key.json".replace(" ", "_")
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=default_name,
            title="Save Bluetooth key",
        )
        if not path:
            return

        try:
            record = export_key(adapter.mac, device.mac)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(record.to_dict(), f, indent=2)
            self.status_var.set(f"Exported key for {device.mac} -> {path}")
            messagebox.showinfo("Export successful", f"Key exported to:\n{path}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Export failed", str(exc))
            self.status_var.set("Export failed")

    def on_import(self):
        adapter = self._get_selected_adapter()
        device = self._get_selected_device()
        if adapter is None or device is None:
            messagebox.showerror("Selection required", "Select an adapter and device first.")
            return

        path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Select Bluetooth key JSON",
        )
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            record = BtKeyRecord.from_dict(data)
            record.adapter_mac = adapter.mac
            record.device_mac = device.mac
            import_key(record)
            self.status_var.set(f"Imported key for {device.mac}")
            messagebox.showinfo(
                "Import successful",
                "Key imported. You may need to toggle Bluetooth or reboot for changes to apply.",
            )
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Import failed", str(exc))
            self.status_var.set("Import failed")


def main():
    if platform.system() != "Windows":
        print("This tool is intended for Windows.")
        return

    app = BtKeyGui()
    app.mainloop()


if __name__ == "__main__":
    main()
