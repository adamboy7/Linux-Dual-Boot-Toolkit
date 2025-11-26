import sys
import os
import ctypes
import subprocess
import shutil
import json
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from ctypes import wintypes
from dataclasses import dataclass
import winreg
import traceback


SYSTEM_FLAG = "--launched-as-system"


BT_KEYS_REG_PATH = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Keys"
BT_DEVICES_REG_PATH = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices"


@dataclass
class BtKeyRecord:
    adapter_mac: str
    device_mac: str
    key_hex: str

    def to_dict(self):
        return {
            "adapter_mac": self.adapter_mac,
            "device_mac": self.device_mac,
            "key_hex": self.key_hex,
        }

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise ValueError("JSON must be an object with adapter_mac, device_mac, and key_hex.")

        required_fields = ["adapter_mac", "device_mac", "key_hex"]
        missing = [f for f in required_fields if f not in data]
        if missing:
            raise ValueError(f"Missing required field(s): {', '.join(missing)}")

        adapter_mac = data["adapter_mac"]
        device_mac = data["device_mac"]
        key_hex = data["key_hex"]

        for name, value in (
            ("adapter_mac", adapter_mac),
            ("device_mac", device_mac),
            ("key_hex", key_hex),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Field '{name}' must be a non-empty string.")

        key_hex_clean = key_hex.strip()
        if len(key_hex_clean) % 2 != 0:
            raise ValueError("key_hex must have an even number of hexadecimal characters.")
        if not all(c in "0123456789abcdefABCDEF" for c in key_hex_clean):
            raise ValueError("key_hex must contain only hexadecimal characters (0-9, A-F).")

        return cls(
            adapter_mac=normalize_mac(adapter_mac),
            device_mac=normalize_mac(device_mac),
            key_hex=key_hex_clean.upper(),
        )


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


def normalize_mac(mac: str) -> str:
    """Normalize MAC to AA:BB:CC:DD:EE:FF."""
    cleaned = mac.replace(":", "").replace("-", "").strip()
    if len(cleaned) != 12:
        raise ValueError(f"Invalid MAC address: {mac}")
    parts = [cleaned[i:i + 2] for i in range(0, 12, 2)]
    return ":".join(p.upper() for p in parts)


def bt_record_to_json_file(record: BtKeyRecord, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record.to_dict(), f, indent=2)


def bt_record_from_json_file(path: str) -> BtKeyRecord:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return BtKeyRecord.from_dict(data)


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


# ---------- Privilege helpers ----------

def get_windows_username():
    """
    Get the Windows account name from the current token using GetUserNameW.
    This is more reliable than environment variables when running under PsExec.
    """
    GetUserNameW = ctypes.windll.advapi32.GetUserNameW
    GetUserNameW.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]

    size = wintypes.DWORD(0)
    GetUserNameW(None, ctypes.byref(size))
    buf = ctypes.create_unicode_buffer(size.value)
    if not GetUserNameW(buf, ctypes.byref(size)):
        return os.environ.get("USERNAME", "")
    return buf.value


def is_system():
    """Return True if the current token belongs to LocalSystem."""
    name = get_windows_username().upper()
    return name == "SYSTEM"


def is_admin():
    """Return True if the process token has administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    """
    Relaunch this script with UAC elevation, then exit the current process.
    """
    script = os.path.abspath(sys.argv[0])
    params = ' '.join(f'"{arg}"' for arg in [script] + sys.argv[1:])

    rc = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        None,
        1
    )

    if int(rc) <= 32:
        messagebox.showerror(
            "Elevation failed",
            "Could not elevate to administrator.\n\n"
            f"Return code: {rc}"
        )
    sys.exit(0)


def relaunch_as_system_via_psexec():
    """
    From an elevated admin process, relaunch this script as SYSTEM using PsExec.
    """
    script = os.path.abspath(sys.argv[0])

    psexec_path = (
        shutil.which("psexec") or
        shutil.which("PsExec64.exe") or
        shutil.which("PsExec.exe")
    )

    if not psexec_path:
        base_dir = os.path.dirname(script)
        for fn in ("PsExec64.exe", "PsExec.exe", "psexec.exe"):
            candidate = os.path.join(base_dir, fn)
            if os.path.isfile(candidate):
                psexec_path = candidate
                break

    if not psexec_path:
        messagebox.showerror(
            "PsExec not found",
            "Unable to locate PsExec.\n\n"
            "Make sure PsExec is either in PATH or in the same folder as this script."
        )
        sys.exit(1)

    args = [psexec_path, "-accepteula", "-i", "-s", sys.executable, script, SYSTEM_FLAG]

    for a in sys.argv[1:]:
        if a != SYSTEM_FLAG:
            args.append(a)

    try:
        subprocess.Popen(args, close_fds=True)
    except Exception as e:
        messagebox.showerror(
            "PsExec launch failed",
            f"Failed to start SYSTEM instance via PsExec:\n\n{e}"
        )
        sys.exit(1)

    sys.exit(0)


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
                key_hex = None
                value_data = value[1]
                if isinstance(value_data, bytes):
                    key_hex = value_data.hex().upper()

                devices.append({
                    "raw": device_mac_raw,
                    "mac": format_mac(device_mac_raw),
                    "name": device_name,
                    "key_hex": key_hex,
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
        self.geometry("580x220")
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

        # Export/Import row
        export_btn = ttk.Button(self, text="Export key to JSON…", command=self.export_key)
        export_btn.grid(row=2, column=0, sticky="ew", padx=(10, 5), pady=(5, 0))

        import_btn = ttk.Button(self, text="Import key from JSON…", command=self.import_key)
        import_btn.grid(row=2, column=1, sticky="ew", padx=(5, 10), pady=(5, 0))

        # Buttons row: Refresh (left) and Exit (right)
        refresh_btn = ttk.Button(self, text="Refresh", command=self.refresh_all)
        refresh_btn.grid(row=3, column=0, sticky="e", padx=(10, 5), pady=(10, 10))

        close_btn = ttk.Button(self, text="Exit", command=self.destroy)
        close_btn.grid(row=3, column=1, sticky="w", padx=(5, 10), pady=(10, 10))

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

    def _get_selected_adapter(self):
        display = self.adapter_var.get()
        adapter = self.display_to_adapter.get(display)
        if not adapter:
            messagebox.showerror("No adapter selected", "Please select a Bluetooth adapter.")
            return None
        return adapter

    def _get_selected_device(self):
        display = self.device_var.get()
        device = self.display_to_device.get(display)
        if not device:
            messagebox.showerror("No device selected", "Please select a paired device.")
            return None
        return device

    def _read_device_key_hex(self, adapter_raw: str, device_raw: str) -> str:
        key_path = BT_KEYS_REG_PATH + "\\" + adapter_raw
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as adap_key:
                value_data, _ = winreg.QueryValueEx(adap_key, device_raw)
        except FileNotFoundError:
            raise RuntimeError("Bluetooth key not found in registry for the selected device.")
        except PermissionError:
            raise PermissionError(
                "Unable to read the Bluetooth key from the registry.\n"
                "Try running this script as SYSTEM or with elevated privileges."
            )

        if not isinstance(value_data, (bytes, bytearray)):
            raise RuntimeError("Unexpected registry data type for the Bluetooth key.")

        return bytes(value_data).hex().upper()

    def export_key(self):
        adapter = self._get_selected_adapter()
        device = self._get_selected_device()
        if not adapter or not device:
            return

        try:
            key_hex = self._read_device_key_hex(adapter["raw"], device["raw"])
            record = BtKeyRecord(
                adapter_mac=format_mac(adapter["raw"]),
                device_mac=format_mac(device["raw"]),
                key_hex=key_hex,
            )
        except Exception as e:
            messagebox.showerror("Export failed", str(e))
            return

        filepath = filedialog.asksaveasfilename(
            title="Export key to JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not filepath:
            return

        try:
            bt_record_to_json_file(record, filepath)
        except Exception as e:
            messagebox.showerror("Export failed", f"Unable to write JSON file:\n\n{e}")
            return

        messagebox.showinfo(
            "Export successful",
            f"Exported key for {device['name']} ({device['mac']}) to:\n{filepath}",
        )

    def import_key(self):
        adapter = self._get_selected_adapter()
        device = self._get_selected_device()
        if not adapter or not device:
            return

        filepath = filedialog.askopenfilename(
            title="Import key from JSON",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not filepath:
            return

        try:
            record = bt_record_from_json_file(filepath)
        except Exception as e:
            messagebox.showerror("Import failed", f"Invalid JSON file:\n\n{e}")
            return

        try:
            selected_adapter_mac = normalize_mac(format_mac(adapter["raw"]))
            selected_device_mac = normalize_mac(format_mac(device["raw"]))
        except ValueError as e:
            messagebox.showerror("Import failed", str(e))
            return

        if (record.adapter_mac != selected_adapter_mac) or (record.device_mac != selected_device_mac):
            if not messagebox.askyesno(
                "Confirm adapter/device mismatch",
                (
                    "The selected adapter/device differ from the JSON file.\n\n"
                    f"Selected adapter: {selected_adapter_mac}\n"
                    f"File adapter:     {record.adapter_mac}\n\n"
                    f"Selected device:  {selected_device_mac}\n"
                    f"File device:      {record.device_mac}\n\n"
                    "Import using the adapter/device from the file?"
                ),
            ):
                return

        try:
            key_bytes = bytes.fromhex(record.key_hex)
        except ValueError:
            messagebox.showerror("Import failed", "key_hex is not valid hexadecimal data.")
            return

        record_adapter_raw = record.adapter_mac.replace(":", "").replace("-", "").lower()
        record_device_raw = record.device_mac.replace(":", "").replace("-", "").lower()

        key_path = BT_KEYS_REG_PATH + "\\" + record_adapter_raw
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                key_path,
                0,
                winreg.KEY_SET_VALUE,
            ) as adap_key:
                winreg.SetValueEx(adap_key, record_device_raw, 0, winreg.REG_BINARY, key_bytes)
        except PermissionError:
            messagebox.showerror(
                "Permission error",
                "Unable to write the Bluetooth key to the registry.\n\n"
                "Make sure you are running this script as SYSTEM or with sufficient privileges.",
            )
            return
        except FileNotFoundError:
            messagebox.showerror(
                "Import failed",
                "Registry path not found for the target adapter. Ensure the device is paired first.",
            )
            return
        except Exception as e:
            messagebox.showerror("Import failed", f"Unexpected error while writing key:\n\n{e}")
            return

        display_device = device["name"] if record.device_mac == selected_device_mac else record.device_mac
        display_adapter = adapter["mac"] if record.adapter_mac == selected_adapter_mac else record.adapter_mac
        messagebox.showinfo(
            "Import successful",
            f"Imported key for {display_device} on adapter {display_adapter} from:\n{filepath}",
        )


def run_app():
    app = BluetoothKeyManagerApp()
    app.mainloop()


def main():
    # If launched via PsExec as SYSTEM, skip the elevation chain.
    if SYSTEM_FLAG in sys.argv or is_system():
        run_app()
        return

    if not is_admin():
        relaunch_as_admin()
        return

    relaunch_as_system_via_psexec()


if __name__ == "__main__":
    main()
