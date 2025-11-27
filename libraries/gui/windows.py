"""Tkinter-based Bluetooth key GUI for Windows systems."""
from __future__ import annotations

import platform
import sys
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from libraries.bluetooth import (
    BluetoothAdapter,
    BluetoothDevice,
    ImportResult,
    WIN_BT_KEYS_REG_PATH,
    get_bluetooth_backend,
    normalize_mac,
    reload_bluetooth,
)
from libraries.bt_gui_logic import BtKeyRecord, bt_record_from_json_file, bt_record_to_json_file
from libraries.permissions import ensure_platform_permissions

SYSTEM_FLAG = "--launched-as-system"

if platform.system() != "Windows":
    raise ImportError("windows GUI module is only available on Windows platforms.")


class BluetoothKeyManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        # Match Linux naming
        self.title("Bluetooth Key Sync (Windows)")
        self.resizable(False, False)

        ensure_platform_permissions(SYSTEM_FLAG)

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

        prev_adapter = self.display_to_adapter.get(self.adapter_var.get())
        prev_device = self.display_to_device.get(self.device_var.get())
        prev_adapter_mac = normalize_mac(prev_adapter.mac) if prev_adapter else None
        prev_device_mac = normalize_mac(prev_device.mac) if prev_device else None

        self.display_to_adapter.clear()
        self.display_to_device.clear()
        self.adapter_combobox["values"] = ()
        self.device_combobox["values"] = ()
        self.adapter_var.set("")
        self.device_var.set("")
        self.set_status("")
        self._load_adapters(prev_adapter_mac, prev_device_mac)

    def _load_adapters(
        self,
        preferred_adapter_mac: str | None = None,
        preferred_device_mac: str | None = None,
    ):
        try:
            adapters = self.backend.list_adapters()
        except PermissionError:
            messagebox.showerror(
                "Permission error",
                "Unable to read Bluetooth keys from the registry.\n\n"
                "Make sure you are running this script as SYSTEM or with "
                "sufficient privileges.",
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
                f"HKLM\\{WIN_BT_KEYS_REG_PATH}",
            )
            self.after(100, self.destroy)
            return

        normalized_preferred_adapter = (
            normalize_mac(preferred_adapter_mac) if preferred_adapter_mac else None
        )
        display_values = []
        selected_index: int | None = None
        for idx, adapter in enumerate(adapters):
            display = f"{adapter.name} ({adapter.mac})"
            self.display_to_adapter[display] = adapter
            display_values.append(display)
            if normalized_preferred_adapter and normalize_mac(adapter.mac) == normalized_preferred_adapter:
                selected_index = idx

        self.adapter_combobox["values"] = display_values

        if display_values:
            fallback_status = None
            if selected_index is not None:
                self.adapter_combobox.current(selected_index)
                self.on_adapter_selected(preferred_device_mac)
            else:
                self.adapter_combobox.current(0)
                if preferred_adapter_mac:
                    fallback_status = (
                        f"Previous adapter {preferred_adapter_mac} not available; "
                        f"showing {self.adapter_var.get()}."
                    )
                self.on_adapter_selected(fallback_message=fallback_status)

    def on_adapter_selected(
        self,
        event=None,
        preferred_device_mac: str | None = None,
        fallback_message: str | None = None,
    ):
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
                "sufficient privileges.",
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

        normalized_preferred_device = (
            normalize_mac(preferred_device_mac) if preferred_device_mac else None
        )
        selected_index: int | None = None
        dev_display_values = []
        for idx, dev in enumerate(devices):
            dev_display = f"{dev.name} ({dev.mac})"
            self.display_to_device[dev_display] = dev
            dev_display_values.append(dev_display)
            if normalized_preferred_device and normalize_mac(dev.mac) == normalized_preferred_device:
                selected_index = idx

        self.device_combobox["values"] = dev_display_values
        status_parts: list[str] = []
        if fallback_message:
            status_parts.append(fallback_message)

        if selected_index is not None:
            self.device_combobox.current(selected_index)
            status_parts.append(
                f"Found {len(devices)} device(s) for adapter {adapter.mac}."
            )
        else:
            self.device_combobox.current(0)
            device_fallback = None
            if preferred_device_mac:
                device_fallback = (
                    f"Device {preferred_device_mac} not available; "
                    f"showing {self.device_var.get()}."
                )
                status_parts.append(device_fallback)
            status_parts.append(
                f"Found {len(devices)} device(s) for adapter {adapter.mac}."
            )

        self.set_status(" ".join(status_parts).strip())
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

    def _adapter_mismatch_prompt(self, selected_adapter: str, file_adapter: str) -> str:
        """Return one of "trust", "override", or "exit" based on user selection."""

        dialog = tk.Toplevel(self)
        dialog.title("Adapter mismatch")
        dialog.transient(self)
        dialog.resizable(False, False)

        frame = ttk.Frame(dialog, padding=(12, 12, 12, 12))
        frame.grid(row=0, column=0, sticky="nsew")

        message = (
            "The selected adapter differs from the JSON file.\n\n"
            f"Selected adapter: {selected_adapter}\n"
            f"File adapter:     {file_adapter}\n\n"
            "Choose how to proceed:"
        )
        label = ttk.Label(frame, text=message, justify="left")
        label.grid(row=0, column=0, sticky="w")

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=1, column=0, sticky="e", pady=(10, 0))

        choice: dict[str, str] = {"value": "exit"}

        def close_with(value: str) -> None:
            choice["value"] = value
            dialog.destroy()

        ttk.Button(button_frame, text="Trust File", command=lambda: close_with("trust")).grid(
            row=0, column=0, padx=4
        )
        ttk.Button(
            button_frame, text="Override Selection", command=lambda: close_with("override")
        ).grid(row=0, column=1, padx=4)
        ttk.Button(button_frame, text="Exit", command=lambda: close_with("exit")).grid(
            row=0, column=2, padx=(4, 0)
        )

        dialog.protocol("WM_DELETE_WINDOW", lambda: close_with("exit"))
        dialog.grab_set()
        dialog.wait_window()
        return choice["value"]

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

        if record.device_mac != selected_device_mac:
            messagebox.showerror(
                "Device mismatch",
                (
                    "The selected device does not match the JSON file.\n\n"
                    f"Selected device: {selected_device_mac}\n"
                    f"File device:     {record.device_mac}"
                ),
            )
            return

        import_record = record

        if record.adapter_mac != selected_adapter_mac:
            choice = self._adapter_mismatch_prompt(selected_adapter_mac, record.adapter_mac)
            if choice == "exit":
                return
            if choice == "override":
                import_record = BtKeyRecord(
                    adapter_mac=selected_adapter_mac,
                    device_mac=selected_device_mac,
                    key_hex=record.key_hex,
                )

        try:
            import_result: ImportResult | None = self.backend.import_key(import_record)
        except Exception as e:
            messagebox.showerror(
                "Import failed",
                f"Unexpected error while writing key:\n\n{e}",
            )
            return

        display_device = device.name
        display_adapter = (
            adapter.mac if import_record.adapter_mac == selected_adapter_mac else import_record.adapter_mac
        )

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


def run_windows_gui() -> None:
    if platform.system() != "Windows":
        print("This GUI tool currently only supports Windows.")
        sys.exit(1)

    ensure_platform_permissions(SYSTEM_FLAG)

    app = BluetoothKeyManagerApp()
    app.mainloop()


__all__ = ["run_windows_gui", "BluetoothKeyManagerApp"]
