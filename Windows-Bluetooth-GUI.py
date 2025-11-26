import os
import platform
import subprocess
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import traceback
import ctypes
from ctypes import wintypes
import shutil


if platform.system() != "Windows":
    print("This tool can only be run on Windows.")
    sys.exit(1)

import winreg


BT_KEYS_REG_PATH = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Keys"
BT_DEVICES_REG_PATH = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices"

# Constants for privilege detection
TOKEN_QUERY = 0x0008
TokenUser = 1
LOCAL_SYSTEM_SID = "S-1-5-18"


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", wintypes.LPVOID),
        ("Attributes", wintypes.DWORD),
    ]


class TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", SID_AND_ATTRIBUTES)]


def _get_current_user_sid():
    """Return the SID of the current process token as a string, or None on error."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        return None

    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, TokenUser, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, TokenUser, buf, needed, ctypes.byref(needed)):
            return None

        token_user = ctypes.cast(buf, ctypes.POINTER(TOKEN_USER)).contents
        sid_ptr = token_user.User.Sid

        string_sid = ctypes.c_wchar_p()
        if not advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(string_sid)):
            return None

        try:
            return string_sid.value
        finally:
            kernel32.LocalFree(string_sid)

    finally:
        kernel32.CloseHandle(token)


def is_system_user() -> bool:
    """Determine whether the current process is running as LocalSystem."""
    sid = _get_current_user_sid()
    if sid:
        return sid == LOCAL_SYSTEM_SID
    return os.environ.get("USERNAME", "").upper() == "SYSTEM"


def is_user_admin() -> bool:
    """Return True if the current process token is elevated (Administrator)."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_with_admin():
    """Trigger a UAC prompt and re-run this script as Administrator."""
    params = " ".join([f'"{arg}"' if " " in arg else arg for arg in [__file__, *sys.argv[1:]]])
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    except Exception:
        ret = 0

    if ret <= 32:
        messagebox.showerror(
            "Elevation failed",
            "Could not prompt for Administrator privileges.\n\n"
            "Please re-run this script as Administrator manually.",
        )
    sys.exit(0)


def _find_psexec():
    """Attempt to locate psexec.exe either in PATH or alongside this script."""
    from_path = shutil.which("psexec")
    if from_path:
        return from_path

    local_copy = os.path.join(os.path.dirname(os.path.abspath(__file__)), "psexec.exe")
    if os.path.exists(local_copy):
        return local_copy
    return None


def relaunch_as_system():
    """Use psexec to relaunch the script in an interactive LocalSystem session."""
    psexec_path = _find_psexec()
    if not psexec_path:
        messagebox.showerror(
            "psexec not found",
            "psexec.exe was not found in PATH or next to the script.\n\n"
            "Place psexec.exe beside this file or add it to PATH, then try again.",
        )
        sys.exit(1)

    cmd = [
        psexec_path,
        "-i",
        "-s",
        sys.executable,
        os.path.abspath(__file__),
        *sys.argv[1:],
    ]

    try:
        completed = subprocess.run(cmd)
        if completed.returncode != 0:
            messagebox.showerror(
                "SYSTEM relaunch failed",
                "psexec did not complete successfully.\n\n"
                "Ensure PsExec is installed and you approved the license dialog.",
            )
    except FileNotFoundError:
        messagebox.showerror(
            "psexec not found",
            "psexec.exe could not be executed.\n\n"
            "Place psexec.exe beside this file or add it to PATH, then try again.",
        )
    except Exception:
        messagebox.showerror(
            "SYSTEM relaunch failed",
            "Unexpected error while invoking psexec:\n\n" + traceback.format_exc(),
        )
    finally:
        sys.exit(0)


def ensure_required_privileges():
    """Ensure we are running as LocalSystem; otherwise try to elevate automatically."""
    root = tk._default_root
    created_root = False

    if root is None:
        root = tk.Tk()
        root.withdraw()
        created_root = True

    if is_system_user():
        if created_root:
            root.destroy()
        return

    if not is_user_admin():
        answer = messagebox.askyesno(
            "Administrator privileges required",
            "Bluetooth keys are only accessible with elevated rights.\n\n",
            "Click Yes to relaunch with Administrator privileges.",
        )
        if created_root:
            root.destroy()
        if answer:
            relaunch_with_admin()
        sys.exit(0)

    # We are Administrator but not LocalSystem
    proceed = messagebox.askyesno(
        "LocalSystem privileges required",
        "Bluetooth link keys require SYSTEM privileges.\n\n",
        "Click Yes to relaunch using psexec as LocalSystem.",
    )
    if created_root:
        root.destroy()
    if proceed:
        relaunch_as_system()
    sys.exit(0)


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
    ensure_required_privileges()
    app = BluetoothKeyManagerApp()
    app.mainloop()
