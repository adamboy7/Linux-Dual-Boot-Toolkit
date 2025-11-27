import platform
import sys

if platform.system() != "Windows":
    print("This GUI tool currently only supports Windows.")
    sys.exit(1)

import traceback
import tkinter as tk
from tkinter import filedialog, ttk, messagebox

from libraries.bluetooth import (
    BluetoothAdapter,
    BluetoothDevice,
    ImportResult,
    WIN_BT_KEYS_REG_PATH,
    normalize_mac,
    get_bluetooth_backend,
    reload_bluetooth,
)
from libraries.bt_gui_logic import (
    bt_record_from_json_file,
    bt_record_to_json_file,
)
from libraries.permissions import ensure_platform_permissions


SYSTEM_FLAG = "--launched-as-system"


class BluetoothKeyManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        # Match Linux naming
        self.title("Bluetooth Key Sync (Windows)")
        self.resizable(False, False)

        self.backend = get_bluetooth_backend()

        self.display_to_adapter: dict[str, BluetoothAdapter] = {}
        self.display_to_device: dict[str, BluetoothDevice] = {}

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

        # Button row: export/import (match Linux layout)
        button_frame = ttk.Frame(root)
        button_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(5, 5))
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)

        export_btn = ttk.Button(button_frame, text="Export key to JSON…", command=self.export_key)
        export_btn.grid(row=0, column=0, sticky="ew", padx=(0, 4))

        import_btn = ttk.Button(button_frame, text="Import key from JSON…", command=self.import_key)
        import_btn.grid(row=0, column=1, sticky="ew", padx=4)

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
            adapters = self.backend.list_adapters()
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
            display = f"{adapter.name} ({adapter.mac})"
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
            devices = self.backend.list_devices(adapter)
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
            self.set_status(f"No devices found for adapter {adapter.mac}.")
            return

        dev_display_values = []
        for dev in devices:
            dev_display = f"{dev.name} ({dev.mac})"
            self.display_to_device[dev_display] = dev
            dev_display_values.append(dev_display)

        self.device_combobox["values"] = dev_display_values
        self.device_combobox.current(0)
        self.set_status(f"Found {len(devices)} device(s) for adapter {adapter.mac}.")
        self.on_device_selected()

    def on_device_selected(self, event=None):
        # Hook left in case we want to show extra info later
        pass

    def _get_selected_adapter(self) -> BluetoothAdapter | None:
        display = self.adapter_var.get()
        adapter = self.display_to_adapter.get(display)
        if not adapter:
            messagebox.showerror("No adapter selected", "Please select a Bluetooth adapter.")
            return None
        return adapter

    def _get_selected_device(self) -> BluetoothDevice | None:
        display = self.device_var.get()
        device = self.display_to_device.get(display)
        if not device:
            messagebox.showerror("No device selected", "Please select a paired device.")
            return None
        return device

    def export_key(self):
        adapter = self._get_selected_adapter()
        device = self._get_selected_device()
        if not adapter or not device:
            return

        try:
            record = self.backend.export_key(adapter, device)
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
            f"Exported key for {device.name} ({device.mac}) to:\n{filepath}",
        )
        self.set_status(f"Exported key for {device.name} to {filepath}")

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

        selected_adapter_mac = normalize_mac(adapter.mac)
        selected_device_mac = normalize_mac(device.mac)

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
            import_result: ImportResult | None = self.backend.import_key(record)
        except Exception as e:
            messagebox.showerror(
                "Import failed",
                f"Unexpected error while writing key:\n\n{e}",
            )
            return

        display_device = device.name if record.device_mac == selected_device_mac else record.device_mac
        display_adapter = adapter.mac if record.adapter_mac == selected_adapter_mac else record.adapter_mac

        backup_path = import_result.backup_path if import_result else None
        registry_backups = import_result.registry_backups if import_result else None

        backup_line = f"\nExisting registry value backed up to:\n{backup_path}" if backup_path else ""
        registry_line = ""
        if registry_backups:
            registry_line = "\nRegistry backups saved to:\n" + "\n".join(registry_backups.values())
        messagebox.showinfo(
            "Import successful",
            f"Imported key for {display_device} on adapter {display_adapter} from:\n{filepath}{backup_line}{registry_line}",
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


def main():
    ensure_platform_permissions(SYSTEM_FLAG)

    app = BluetoothKeyManagerApp()
    app.mainloop()


if __name__ == "__main__":
    main()

