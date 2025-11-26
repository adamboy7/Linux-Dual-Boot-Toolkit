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

from libraries.backup_validation import parse_backup_payload, validate_backup_matches
from libraries.bluetooth_utils import (
    WIN_BT_KEYS_REG_PATH,
    format_mac,
    get_bluetooth_adapters,
    get_devices_for_adapter,
    normalize_mac,
    read_device_key_hex,
    reload_bluetooth,
)
from libraries.bt_gui_logic import BtKeyRecord, bt_record_from_json_file, bt_record_to_json_file
from libraries.permissions import ensure_platform_permissions


SYSTEM_FLAG = "--launched-as-system"


class BluetoothKeyManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        # Match Linux naming
        self.title("Bluetooth Key Sync (Windows)")
        self.resizable(False, False)

        self.display_to_adapter = {}
        self.display_to_device = {}

        # Track directories where the user is saving/loading files so we can
        # discover backups created alongside them.
        self.backup_search_dirs = [os.getcwd()]

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
        try:
            adapters = get_bluetooth_adapters()
        except PermissionError:
            messagebox.showerror(
                "Permission error",
                "Unable to read Bluetooth keys from the registry.\n\n"
                "Make sure you are running this script as SYSTEM or with "
                "sufficient privileges."
            )
            self.after(100, self.destroy)
            return
        except Exception:
            messagebox.showerror(
                "Error",
                "Unexpected error while reading Bluetooth adapters:\n\n"
                + traceback.format_exc(),
            )
            self.after(100, self.destroy)
            return

        if not adapters:
            messagebox.showerror(
                "No adapters found",
                "No Bluetooth adapter keys were found under:\n\n"
                f"HKLM\\{WIN_BT_KEYS_REG_PATH}"
            )
            self.after(100, self.destroy)
            return

        display_values = []
        for adapter in adapters:
            display = f"{adapter.get('name', adapter['mac'])} ({adapter['mac']})"
            if adapter.get("is_default"):
                display += " [default]"
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

        try:
            devices = get_devices_for_adapter(adapter["raw"])
        except FileNotFoundError:
            devices = []
        except PermissionError:
            messagebox.showerror(
                "Permission error",
                "Unable to read Bluetooth device keys from the registry.\n\n"
                "Make sure you are running this script as SYSTEM or with "
                "sufficient privileges."
            )
            return
        except Exception:
            messagebox.showerror(
                "Error",
                "Unexpected error while reading Bluetooth devices:\n\n"
                + traceback.format_exc(),
            )
            return

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
        found = []
        seen_paths = set()

        for directory in self.backup_search_dirs:
            pattern = os.path.join(directory, "bt_key_backup_*.json")
            for path in glob.glob(pattern):
                if path not in seen_paths:
                    seen_paths.add(path)
                    found.append(path)

        return sorted(found, key=os.path.getmtime, reverse=True)

    def _note_file_location(self, filepath: str):
        directory = os.path.dirname(filepath) or os.getcwd()
        if directory not in self.backup_search_dirs:
            self.backup_search_dirs.append(directory)

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

    def export_key(self):
        adapter = self._get_selected_adapter()
        device = self._get_selected_device()
        if not adapter or not device:
            return

        try:
            key_hex = read_device_key_hex(adapter["raw"], device["raw"])
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

        self._note_file_location(filepath)

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

        self._note_file_location(filepath)

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

        key_path = WIN_BT_KEYS_REG_PATH + "\\" + record_adapter_raw
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

                self._note_file_location(backup_path)
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
        adapter = self._get_selected_adapter()
        if adapter is None:
            return

        device = self.display_to_device.get(self.device_var.get())
        if device is None:
            self.set_status("No device selected; will infer device from backup metadata.")

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
            expected_adapter = normalize_mac(adapter["mac"])
            expected_device = normalize_mac(device["mac"]) if device else None
        except ValueError as e:
            messagebox.showerror("Restore failed", str(e))
            return

        try:
            parsed_backup = parse_backup_payload(filepath)
        except ValueError as e:
            messagebox.showerror("Restore failed", str(e))
            return
        except Exception as e:
            messagebox.showerror("Restore failed", f"Unable to read backup file:\n\n{e}")
            return

        if not validate_backup_matches(
            expected_adapter,
            expected_device or parsed_backup.payload.get("device_mac"),
            filepath,
            lambda msg, title=None: messagebox.showerror(title or "Restore blocked", msg),
        ):
            return

        payload = parsed_backup.payload
        key_path = payload["key_path"]
        value_name = payload["value_name"]
        reg_type = payload["reg_type"]
        reg_value = payload["reg_value"]
        created_at = payload["created_at"]

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
