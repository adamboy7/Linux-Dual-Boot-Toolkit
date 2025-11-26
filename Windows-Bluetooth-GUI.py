import tkinter as tk
from tkinter import ttk, messagebox
import winreg
import traceback


BT_KEYS_REG_PATH = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Keys"
BT_DEVICES_REG_PATH = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices"


def format_mac(raw_key_name: str) -> str:
    """
    Convert hex string like '001a7dda710b' to '00:1A:7D:DA:71:0B'.
    If the length is unexpected, just return the original string.
    """
    s = raw_key_name.replace(":", "").replace("-", "").strip()
    if len(s) != 12:
        return raw_key_name
    s = s.lower()
    parts = [s[i:i + 2] for i in range(0, 12, 2)]
    return ":".join(p.upper() for p in parts)


def get_bluetooth_adapters():
    """
    Enumerate Bluetooth adapters from the registry.

    Returns a list of dicts:
    [
        {"raw": "001a7dda710b", "mac": "00:1A:7D:DA:71:0B"},
        ...
    ]
    """
    adapters = []

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, BT_KEYS_REG_PATH) as key:
            index = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, index)
                except OSError:
                    break

                adapters.append({
                    "raw": subkey_name,
                    "mac": format_mac(subkey_name),
                })
                index += 1

    except FileNotFoundError:
        return adapters
    except PermissionError:
        messagebox.showerror(
            "Permission error",
            "Unable to read Bluetooth keys from the registry.\n\n"
            "Make sure you are running this script as SYSTEM or with "
            "sufficient privileges."
        )
    except Exception:
        messagebox.showerror(
            "Error",
            "Unexpected error while reading Bluetooth adapters:\n\n"
            + traceback.format_exc()
        )

    return adapters


def _decode_bt_name(raw_value):
    """
    Decode Bluetooth name bytes to a Python string.

    Some devices store UTF-16-LE, others store ASCII/UTF-8 bytes.
    We heuristically detect UTF-16; otherwise we treat it as single-byte text.
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
            # Try UTF-8 first, then fall back to Windows ANSI (mbcs)
            try:
                s = raw_value.decode("utf-8", errors="ignore")
            except Exception:
                try:
                    s = raw_value.decode("mbcs", errors="ignore")
                except Exception:
                    s = ""

        return s.rstrip("\x00").strip()

    elif isinstance(raw_value, str):
        return raw_value.strip()

    return ""


def get_device_display_name(device_mac_raw: str) -> str:
    """
    For a given device MAC (raw, e.g. 'd08a553113c1'), look up its
    FriendlyName or Name in the Devices tree.

    Fallback order:
      FriendlyName (if non-zero) -> Name (if non-zero) -> formatted MAC
    """
    key_path = BT_DEVICES_REG_PATH + "\\" + device_mac_raw
    formatted_mac = format_mac(device_mac_raw)

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as dev_key:
            # Try FriendlyName first
            for value_name in ("FriendlyName", "Name"):
                try:
                    raw_value, _ = winreg.QueryValueEx(dev_key, value_name)
                except FileNotFoundError:
                    continue

                decoded = _decode_bt_name(raw_value)
                if decoded:
                    return decoded

    except FileNotFoundError:
        # No Devices entry; fall back to MAC
        pass
    except PermissionError:
        # Silent; overall logic will still work with MAC as fallback
        pass
    except Exception:
        # Don't hard-fail the whole UI; just log to a dialog once.
        traceback.print_exc()

    return formatted_mac


def get_devices_for_adapter(adapter_raw: str):
    """
    Enumerate devices paired to a given adapter.

    Returns a list of dicts:
    [
        {
            "raw": "d08a553113c1",
            "mac": "D0:8A:55:31:13:C1",
            "name": "Hesh 2 Wireless"
        },
        ...
    ]
    """
    devices = []

    key_path = BT_KEYS_REG_PATH + "\\" + adapter_raw

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as adap_key:
            index = 0
            while True:
                try:
                    value = winreg.EnumValue(adap_key, index)
                except OSError:
                    break

                device_mac_raw = value[0]  # value name
                device_name = get_device_display_name(device_mac_raw)

                devices.append({
                    "raw": device_mac_raw,
                    "mac": format_mac(device_mac_raw),
                    "name": device_name,
                })

                index += 1

    except FileNotFoundError:
        # No devices for this adapter
        pass
    except PermissionError:
        messagebox.showerror(
            "Permission error",
            "Unable to read Bluetooth device keys from the registry.\n\n"
            "Make sure you are running this script as SYSTEM or with "
            "sufficient privileges."
        )
    except Exception:
        messagebox.showerror(
            "Error",
            "Unexpected error while reading Bluetooth devices:\n\n"
            + traceback.format_exc()
        )

    return devices


class BluetoothKeyManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Bluetooth Key Manager")
        self.geometry("550x170")
        self.resizable(False, False)

        self.display_to_adapter = {}
        self.display_to_device = {}

        self._create_widgets()
        self._load_adapters()

    def _create_widgets(self):
        padding = {"padx": 10, "pady": 5}

        # Adapter row
        lbl_adap = ttk.Label(self, text="Bluetooth adapter:")
        lbl_adap.grid(row=0, column=0, sticky="w", **padding)

        self.adapter_var = tk.StringVar()
        self.adapter_combobox = ttk.Combobox(
            self,
            textvariable=self.adapter_var,
            state="readonly",
            width=45,
        )
        self.adapter_combobox.grid(row=0, column=1, sticky="ew", **padding)
        self.adapter_combobox.bind("<<ComboboxSelected>>", self.on_adapter_selected)

        # Device row
        lbl_dev = ttk.Label(self, text="Paired device:")
        lbl_dev.grid(row=1, column=0, sticky="w", **padding)

        self.device_var = tk.StringVar()
        self.device_combobox = ttk.Combobox(
            self,
            textvariable=self.device_var,
            state="readonly",
            width=45,
        )
        self.device_combobox.grid(row=1, column=1, sticky="ew", **padding)
        self.device_combobox.bind("<<ComboboxSelected>>", self.on_device_selected)

        # Buttons row: Refresh (left) and Exit (right)
        refresh_btn = ttk.Button(self, text="Refresh", command=self.refresh_all)
        refresh_btn.grid(row=2, column=0, sticky="e", padx=(10, 5), pady=(10, 10))

        close_btn = ttk.Button(self, text="Exit", command=self.destroy)
        close_btn.grid(row=2, column=1, sticky="w", padx=(5, 10), pady=(10, 10))

        # Allow combobox column to stretch
        self.columnconfigure(1, weight=1)

    def refresh_all(self):
        """Reload adapter and device lists from the registry."""
        # Clear mappings and combo contents
        self.display_to_adapter.clear()
        self.display_to_device.clear()
        self.adapter_combobox["values"] = ()
        self.device_combobox["values"] = ()
        self.adapter_var.set("")
        self.device_var.set("")
        self._load_adapters()

    def _load_adapters(self):
        adapters = get_bluetooth_adapters()

        if not adapters:
            messagebox.showerror(
                "No adapters found",
                "No Bluetooth adapter keys were found under:\n\n"
                f"HKLM\\{BT_KEYS_REG_PATH}"
            )
            self.after(100, self.destroy)
            return

        display_values = []
        for adapter in adapters:
            display = f"{adapter['mac']} ({adapter['raw']})"
            self.display_to_adapter[display] = adapter
            display_values.append(display)

        self.adapter_combobox["values"] = display_values

        if display_values:
            self.adapter_combobox.current(0)
            self.on_adapter_selected()

    def on_adapter_selected(self, event=None):
        display = self.adapter_var.get()
        adapter = self.display_to_adapter.get(display)

        # Load devices for this adapter
        self.display_to_device.clear()
        self.device_combobox["values"] = ()
        self.device_var.set("")

        if not adapter:
            return

        devices = get_devices_for_adapter(adapter["raw"])

        if not devices:
            return

        dev_display_values = []
        for dev in devices:
            dev_display = f"{dev['name']} ({dev['mac']})"
            self.display_to_device[dev_display] = dev
            dev_display_values.append(dev_display)

        self.device_combobox["values"] = dev_display_values
        self.device_combobox.current(0)
        self.on_device_selected()

    def on_device_selected(self, event=None):
        # For now we don't need to display anything else when a device is selected,
        # but we keep this hook so we can plug in export/import next.
        pass


if __name__ == "__main__":
    app = BluetoothKeyManagerApp()
    app.mainloop()
