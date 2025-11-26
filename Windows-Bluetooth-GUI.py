import os
import platform
import sys

if platform.system() != "Windows":
    print("This GUI tool currently only supports Windows.")
    sys.exit(1)

import glob
import json
import traceback
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import winreg

from libraries.bluetooth_utils import format_mac, normalize_mac, reload_bluetooth
from libraries.bt_gui_logic import BtKeyRecord, bt_record_from_json_file, bt_record_to_json_file
from libraries.permissions import ensure_platform_permissions


SYSTEM_FLAG = "--launched-as-system"


BT_KEYS_REG_PATH = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Keys"
BT_DEVICES_REG_PATH = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices"


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

        # Match Linux naming
        self.title("Bluetooth Key Sync (Windows)")
        self.resizable(False, False)

        self.display_to_adapter = {}
        self.display_to_device = {}

        self.status_var = tk.StringVar(value="")

        self._create_widgets()
        self._load_adapters()

    def _create_widgets(self):
        # Outer padding frame (similar feel to GTK border_width)
        root = ttk.Frame(self, padding=(10, 10, 10, 10))
        root.grid(row=0, column=0, sticky="nsew")

        # Allow main column to stretch for combos/buttons
        root.columnconfigure(1, weight=1)

        # Adapter row
        lbl_adap = ttk.Label(root, text="Adapter:")
        lbl_adap.grid(row=0, column=0, sticky="w", padx=(0, 6), pady=(0, 5))

        self.adapter_var = tk.StringVar()
        self.adapter_combobox = ttk.Combobox(
            root,
            textvariable=self.adapter_var,
            state="readonly",
            width=45,
        )
        self.adapter_combobox.grid(row=0, column=1, sticky="ew", pady=(0, 5))
        self.adapter_combobox.bind("<<ComboboxSelected>>", self.on_adapter_selected)

        # Device row
        lbl_dev = ttk.Label(root, text="Device:")
        lbl_dev.grid(row=1, column=0, sticky="w", padx=(0, 6), pady=(0, 5))

        self.device_var = tk.StringVar()
        self.device_combobox = ttk.Combobox(
            root,
            textvariable=self.device_var,
            state="readonly",
            width=45,
        )
        self.device_combobox.grid(row=1, column=1, sticky="ew", pady=(0, 5))
        self.device_combobox.bind("<<ComboboxSelected>>", self.on_device_selected)

        # Button row: export/import/restore (match Linux layout)
        button_frame = ttk.Frame(root)
        button_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(5, 5))
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        button_frame.columnconfigure(2, weight=1)

        export_btn = ttk.Button(button_frame, text="Export key to JSON…", command=self.export_key)
        export_btn.grid(row=0, column=0, sticky="ew", padx=(0, 4))

        import_btn = ttk.Button(button_frame, text="Import key from JSON…", command=self.import_key)
        import_btn.grid(row=0, column=1, sticky="ew", padx=4)

        restore_btn = ttk.Button(button_frame, text="Restore backup…", command=self.restore_backup)
        restore_btn.grid(row=0, column=2, sticky="ew", padx=(4, 0))

        # Status row with Refresh + Exit on the right (Linux-style)
        status_frame = ttk.Frame(root)
        status_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        status_frame.columnconfigure(0, weight=1)

        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.grid(row=0, column=0, sticky="w")

        refresh_btn = ttk.Button(status_frame, text="Refresh", command=self.refresh_all)
        refresh_btn.grid(row=0, column=1, sticky="e", padx=(8, 4))

        close_btn = ttk.Button(status_frame, text="Exit", command=self.destroy)
        close_btn.grid(row=0, column=2, sticky="e")

        # Make top-level frame expand if window is resized
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

    def set_status(self, text: str):
        self.status_var.set(text)

    def refresh_all(self):
        """Reload adapter and device lists from the registry."""
        self.display_to_adapter.clear()
        self.display_to_device.clear()
        self.adapter_combobox["values"] = ()
        self.device_combobox["values"] = ()
        self.adapter_var.set("")
        self.device_var.set("")
        self.set_status("")
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
            # Match Linux display: name first if we had one, but here we only
            # know MAC + raw. Keep MAC prominent.
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

        self.display_to_device.clear()
        self.device_combobox["values"] = ()
        self.device_var.set("")

        if not adapter:
            self.set_status("No adapter selected.")
            return

        devices = get_devices_for_adapter(adapter["raw"])

        if not devices:
            self.set_status(f"No devices found for adapter {adapter['mac']}.")
            return

        dev_display_values = []
        for dev in devices:
            dev_display = f"{dev['name']} ({dev['mac']})"
            self.display_to_device[dev_display] = dev
            dev_display_values.append(dev_display)

        self.device_combobox["values"] = dev_display_values
        self.device_combobox.current(0)
        self.set_status(f"Found {len(devices)} device(s) for adapter {adapter['mac']}.")
        self.on_device_selected()

    def on_device_selected(self, event=None):
        # Hook left in case we want to show extra info later
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

    def _find_backup_files(self):
        pattern = os.path.join(os.getcwd(), "bt_key_backup_*.json")
        return sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)

    def _prompt_for_backup_file(self, backups):
        selected = {"path": None}

        dialog = tk.Toplevel(self)
        dialog.title("Select backup to restore")
        dialog.resizable(False, False)
        dialog.transient(self)

        label = ttk.Label(dialog, text="Select a Bluetooth key backup to restore:")
        label.pack(padx=10, pady=(10, 5), anchor="w")

        listbox = tk.Listbox(dialog, width=80, height=min(len(backups), 10))
        for path in backups:
            listbox.insert(tk.END, os.path.basename(path))
        listbox.pack(padx=10, pady=(0, 5), fill="both")

        if backups:
            listbox.selection_set(0)

        def choose_from_list(event=None):
            sel = listbox.curselection()
            if sel:
                selected["path"] = backups[sel[0]]
                dialog.destroy()

        def browse_for_file():
            path = filedialog.askopenfilename(
                title="Restore Bluetooth key backup",
                initialdir=os.path.dirname(backups[0]) if backups else os.getcwd(),
                filetypes=[
                    ("Bluetooth key backups", "bt_key_backup_*.json"),
                    ("JSON files", "*.json"),
                    ("All files", "*.*"),
                ],
            )
            if path:
                selected["path"] = path
                dialog.destroy()

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill="x", padx=10, pady=(5, 10))

        restore_btn = ttk.Button(btn_frame, text="Restore", command=choose_from_list)
        restore_btn.pack(side="left")

        browse_btn = ttk.Button(btn_frame, text="Browse…", command=browse_for_file)
        browse_btn.pack(side="left", padx=(5, 0))

        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=dialog.destroy)
        cancel_btn.pack(side="right")

        listbox.bind("<Double-Button-1>", choose_from_list)
        dialog.grab_set()
        self.wait_window(dialog)
        return selected["path"]

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
        self.set_status(f"Exported key for {device['name']} to {filepath}")

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
        previous_value = None
        previous_value_type = None
        backup_path = None

        # Read the existing registry value so it can be backed up and restored on failure
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as adap_key:
                try:
                    prev_value, prev_type = winreg.QueryValueEx(adap_key, record_device_raw)
                    previous_value = prev_value
                    previous_value_type = prev_type
                except FileNotFoundError:
                    pass
        except PermissionError:
            messagebox.showerror(
                "Permission error",
                "Unable to read the existing Bluetooth key from the registry.\n\n"
                "Make sure you are running this script as SYSTEM or with sufficient privileges.",
            )
            return
        except FileNotFoundError:
            pass
        except Exception as e:
            messagebox.showerror("Import failed", f"Unexpected error while reading existing key:\n\n{e}")
            return

        if previous_value is not None:
            try:
                backup_dir = os.path.dirname(filepath) or os.getcwd()
                timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                backup_filename = (
                    f"bt_key_backup_{record_adapter_raw}_{record_device_raw}_{timestamp}.json"
                )
                backup_path = os.path.join(backup_dir, backup_filename)

                if isinstance(previous_value, (bytes, bytearray)):
                    backup_value = previous_value.hex()
                    value_format = "hex"
                else:
                    backup_value = previous_value
                    value_format = "literal"

                backup_payload = {
                    "key_path": key_path,
                    "value_name": record_device_raw,
                    "value_type": previous_value_type,
                    "value_format": value_format,
                    "value_data": backup_value,
                    "created_at": timestamp,
                }

                with open(backup_path, "w", encoding="utf-8") as backup_file:
                    json.dump(backup_payload, backup_file, indent=2)
            except Exception as e:
                messagebox.showerror(
                    "Import failed",
                    "Unable to create a backup of the existing registry value.\n\n"
                    f"Error: {e}",
                )
                return

        def restore_previous_value():
            if previous_value is None:
                return None
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    key_path,
                    0,
                    winreg.KEY_SET_VALUE,
                ) as adap_key:
                    winreg.SetValueEx(
                        adap_key,
                        record_device_raw,
                        0,
                        previous_value_type if previous_value_type is not None else winreg.REG_BINARY,
                        previous_value,
                    )
                return None
            except Exception as restore_exc:
                return restore_exc

        def format_error_message(base_message: str, restore_error):
            parts = [base_message]
            if backup_path:
                parts.append(f"Backup saved to: {backup_path}")
            if previous_value is not None:
                if restore_error is None:
                    parts.append("Previous value was restored automatically.")
                elif restore_error:
                    parts.append(
                        "Failed to restore the previous value automatically: "
                        f"{restore_error}"
                    )
            return "\n\n".join(parts)

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                key_path,
                0,
                winreg.KEY_SET_VALUE,
            ) as adap_key:
                winreg.SetValueEx(adap_key, record_device_raw, 0, winreg.REG_BINARY, key_bytes)
        except PermissionError:
            restore_error = restore_previous_value()
            messagebox.showerror(
                "Permission error",
                format_error_message(
                    "Unable to write the Bluetooth key to the registry.\n\n"
                    "Make sure you are running this script as SYSTEM or with sufficient privileges.",
                    restore_error,
                ),
            )
            return
        except FileNotFoundError:
            restore_error = restore_previous_value()
            messagebox.showerror(
                "Import failed",
                format_error_message(
                    "Registry path not found for the target adapter. Ensure the device is paired first.",
                    restore_error,
                ),
            )
            return
        except Exception as e:
            restore_error = restore_previous_value()
            messagebox.showerror(
                "Import failed",
                format_error_message(
                    f"Unexpected error while writing key:\n\n{e}",
                    restore_error,
                ),
            )
            return

        display_device = device["name"] if record.device_mac == selected_device_mac else record.device_mac
        display_adapter = adapter["mac"] if record.adapter_mac == selected_adapter_mac else record.adapter_mac
        backup_line = f"\nExisting registry value backed up to:\n{backup_path}" if backup_path else ""
        messagebox.showinfo(
            "Import successful",
            f"Imported key for {display_device} on adapter {display_adapter} from:\n{filepath}{backup_line}",
        )
        self.set_status(f"Imported key for {display_device} on {display_adapter}.")

        if messagebox.askyesno(
            "Reload Bluetooth?",
            "Reload the Windows Bluetooth service now to use the new key?",
        ):
            success, detail = reload_bluetooth()
            if success:
                self.set_status(f"Bluetooth service reloaded via: {detail}")
                messagebox.showinfo(
                    "Bluetooth reloaded", "Bluetooth service was reloaded successfully.",
                )
            else:
                messagebox.showerror(
                    "Reload failed",
                    "Failed to reload Bluetooth automatically.\n\n"
                    f"Attempted: {detail}",
                )

    def restore_backup(self):
        backups = self._find_backup_files()

        if backups:
            filepath = self._prompt_for_backup_file(backups)
        else:
            browse_prompt = (
                "No bt_key_backup_*.json files were found in the current directory.\n\n"
                "Would you like to browse for a backup file?"
            )

            if not messagebox.askyesno("No backups found", browse_prompt):
                return

            filepath = filedialog.askopenfilename(
                title="Restore Bluetooth key backup",
                initialdir=os.getcwd(),
                filetypes=[
                    ("Bluetooth key backups", "bt_key_backup_*.json"),
                    ("JSON files", "*.json"),
                    ("All files", "*.*"),
                ],
            )

        if not filepath:
            return

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                backup_payload = json.load(f)
        except Exception as e:
            messagebox.showerror("Restore failed", f"Unable to read backup file:\n\n{e}")
            return

        required_fields = ["key_path", "value_name", "value_type", "value_format", "value_data"]
        missing = [f for f in required_fields if f not in backup_payload]
        if missing:
            messagebox.showerror(
                "Restore failed",
                f"Backup file is missing required field(s): {', '.join(missing)}",
            )
            return

        key_path = backup_payload.get("key_path")
        value_name = backup_payload.get("value_name")
        value_type = backup_payload.get("value_type")
        value_format = backup_payload.get("value_format")
        value_data = backup_payload.get("value_data")
        created_at = backup_payload.get("created_at")

        if not isinstance(key_path, str) or not key_path.strip():
            messagebox.showerror("Restore failed", "Backup key_path must be a non-empty string.")
            return
        if not isinstance(value_name, str) or not value_name.strip():
            messagebox.showerror("Restore failed", "Backup value_name must be a non-empty string.")
            return

        try:
            reg_type = int(value_type)
        except Exception:
            messagebox.showerror("Restore failed", "Backup value_type must be a valid integer.")
            return

        if value_format == "hex":
            if not isinstance(value_data, str):
                messagebox.showerror(
                    "Restore failed",
                    "Backup value_data must be a hexadecimal string when value_format is 'hex'.",
                )
                return
            try:
                reg_value = bytes.fromhex(value_data)
            except ValueError:
                messagebox.showerror(
                    "Restore failed",
                    "value_data is not valid hexadecimal data and cannot be restored.",
                )
                return
        elif value_format == "literal":
            reg_value = value_data
        else:
            messagebox.showerror(
                "Restore failed",
                "Unsupported value_format in backup file. Expected 'hex' or 'literal'.",
                )
            return

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                key_path,
                0,
                winreg.KEY_SET_VALUE,
            ) as reg_key:
                winreg.SetValueEx(reg_key, value_name, 0, reg_type, reg_value)
        except PermissionError:
            messagebox.showerror(
                "Permission error",
                "Unable to write the Bluetooth key to the registry.\n\n"
                "Make sure you are running this script as SYSTEM or with sufficient privileges.",
            )
            return
        except FileNotFoundError:
            messagebox.showerror(
                "Restore failed",
                "Registry path from the backup file was not found. Ensure the adapter/device still exists.",
            )
            return
        except Exception as e:
            messagebox.showerror(
                "Restore failed",
                f"Unexpected error while writing key back to the registry:\n\n{e}",
            )
            return

        created_line = f" (created at {created_at})" if created_at else ""
        messagebox.showinfo(
            "Restore successful",
            "Restored registry value\n"
            f"HKLM\\{key_path}\\{value_name}{created_line}\n\n"
            f"Source file:\n{filepath}",
        )
        self.set_status("Restored registry value from backup.")

def run_app():
    app = BluetoothKeyManagerApp()
    app.mainloop()


def main():
    ensure_platform_permissions(SYSTEM_FLAG)
    run_app()


if __name__ == "__main__":
    main()
