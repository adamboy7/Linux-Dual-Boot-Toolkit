#!/usr/bin/env python3
"""
Linux-Bluetooth-GUI.py

GTK-based GUI to export/import Bluetooth pairing keys on Linux (BlueZ).

Features:
- Detect adapters from /var/lib/bluetooth
- Detect devices for the selected adapter (names + MACs)
- Export selected device's link key to JSON
- Import link key from JSON into selected device's BlueZ "info" file

Usage:
    python3 Linux-Bluetooth-GUI.py

This script is intended for the Linux side of a dual-boot setup.
You can pair your headphones in Windows, export the key there to JSON,
and then import that JSON here into the selected device.
"""

import json
import platform
import sys

from libraries.bluetooth import (
    BluetoothAdapter,
    BluetoothDevice,
    get_bluetooth_backend,
    reload_bluetooth,
)
from libraries.bt_gui_logic import BtKeyRecord
from libraries.permissions import ensure_platform_permissions


# Only import GTK if on Linux
if platform.system() == "Linux":
    ensure_platform_permissions()
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk
else:
    print("This GUI tool currently only supports Linux (BlueZ).")
    sys.exit(1)

class BtKeyGui(Gtk.Window):
    def __init__(self):
        super().__init__(title="Bluetooth Key Sync (Linux)")
        self.set_border_width(10)
        self.set_default_size(480, 200)

        # Data
        self.backend = get_bluetooth_backend()
        self.adapters: list[BluetoothAdapter] = self.backend.list_adapters()
        self.devices: list[BluetoothDevice] = []

        if not self.adapters:
            self._show_error_and_quit("No Bluetooth adapters found in /var/lib/bluetooth.")
            return

        # Top-level layout
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.add(vbox)

        # Adapter row
        adapter_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        vbox.pack_start(adapter_box, False, False, 0)

        adapter_label = Gtk.Label(label="Adapter:")
        adapter_label.set_xalign(0.0)
        adapter_box.pack_start(adapter_label, False, False, 0)

        self.adapter_store = Gtk.ListStore(str, object)  # display_text, BluetoothAdapter
        self.adapter_combo = Gtk.ComboBox.new_with_model(self.adapter_store)
        renderer_text = Gtk.CellRendererText()
        self.adapter_combo.pack_start(renderer_text, True)
        self.adapter_combo.add_attribute(renderer_text, "text", 0)
        adapter_box.pack_start(self.adapter_combo, True, True, 0)

        # Device row
        device_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        vbox.pack_start(device_box, False, False, 0)

        device_label = Gtk.Label(label="Device:")
        device_label.set_xalign(0.0)
        device_box.pack_start(device_label, False, False, 0)

        self.device_store = Gtk.ListStore(str, object)  # display_text, BluetoothDevice
        self.device_combo = Gtk.ComboBox.new_with_model(self.device_store)
        renderer_text2 = Gtk.CellRendererText()
        self.device_combo.pack_start(renderer_text2, True)
        self.device_combo.add_attribute(renderer_text2, "text", 0)
        device_box.pack_start(self.device_combo, True, True, 0)

        # Buttons
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        vbox.pack_start(button_box, False, False, 0)

        self.export_button = Gtk.Button(label="Export key to JSON…")
        self.export_button.connect("clicked", self.on_export_clicked)
        button_box.pack_start(self.export_button, True, True, 0)

        self.import_button = Gtk.Button(label="Import key from JSON…")
        self.import_button.connect("clicked", self.on_import_clicked)
        button_box.pack_start(self.import_button, True, True, 0)
        # Status row with refresh button on the right
        status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        vbox.pack_start(status_box, False, False, 4)

        self.status_label = Gtk.Label(label="")
        self.status_label.set_xalign(0.0)
        status_box.pack_start(self.status_label, True, True, 0)

        self.refresh_button = Gtk.Button(label="Refresh")
        self.refresh_button.connect("clicked", self.on_refresh_clicked)
        status_box.pack_start(self.refresh_button, False, False, 0)

        self.exit_button = Gtk.Button(label="Exit")
        self.exit_button.connect("clicked", Gtk.main_quit)
        status_box.pack_start(self.exit_button, False, False, 0)

        # Populate adapters and select default
        self._populate_adapters()

        # If there's only one adapter, we can leave selection as-is; the user
        # still sees which one it is, but they don't *have* to change it.

        self.adapter_combo.connect("changed", self.on_adapter_changed)

        self.connect("destroy", Gtk.main_quit)
        self.show_all()

    # ----- UI helpers -----

    def _show_error_dialog(self, message: str, title: str = "Error"):
        dialog = Gtk.MessageDialog(
            transient_for=self,
            flags=0,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK,
            text=title,
        )
        dialog.format_secondary_text(message)
        dialog.run()
        dialog.destroy()

    def _show_info_dialog(self, *messages: str, title: str = "Info"):
        message = "".join(messages) if len(messages) > 1 else (messages[0] if messages else "")
        dialog = Gtk.MessageDialog(
            transient_for=self,
            flags=0,
            message_type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.OK,
            text=title,
        )
        dialog.format_secondary_text(message)
        dialog.run()
        dialog.destroy()

    def _ask_yes_no(self, message: str, title: str = "Confirm") -> bool:
        dialog = Gtk.MessageDialog(
            transient_for=self,
            flags=0,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text=title,
        )
        dialog.format_secondary_text(message)
        response = dialog.run()
        dialog.destroy()
        return response == Gtk.ResponseType.YES

    def _show_error_and_quit(self, message: str):
        # Simple stdout fallback in case GTK isn't fully up yet
        print("ERROR:", message, file=sys.stderr)
        dlg = Gtk.MessageDialog(
            transient_for=None,
            flags=0,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK,
            text="Error",
        )
        dlg.format_secondary_text(message)
        dlg.run()
        dlg.destroy()
        Gtk.main_quit()

    def set_status(self, text: str):
        self.status_label.set_text(text)

    # ----- Data population -----

    def _populate_adapters(
        self,
        preferred_adapter_mac: str | None = None,
        preferred_device_mac: str | None = None,
    ):
        self.adapter_store.clear()
        default_iter = None
        selected_iter = None
        for adapter in self.adapters:
            display = f"{adapter.name} ({adapter.mac})"
            if adapter.is_default:
                display += " [default]"
            iter_ = self.adapter_store.append([display, adapter])
            if adapter.is_default:
                default_iter = iter_
            if preferred_adapter_mac and adapter.mac == preferred_adapter_mac:
                selected_iter = iter_

        if selected_iter is not None:
            self.adapter_combo.set_active_iter(selected_iter)
        elif default_iter is not None:
            self.adapter_combo.set_active_iter(default_iter)
        else:
            self.adapter_combo.set_active(0)

        # Trigger initial device list
        if selected_iter is not None:
            self._reload_devices_for_selected_adapter(preferred_device_mac)
        else:
            self._reload_devices_for_selected_adapter()

    def _get_selected_adapter(self) -> BluetoothAdapter | None:
        tree_iter = self.adapter_combo.get_active_iter()
        if tree_iter is None:
            return None
        model = self.adapter_combo.get_model()
        return model[tree_iter][1]  # BluetoothAdapter

    def _get_selected_device(self) -> BluetoothDevice | None:
        tree_iter = self.device_combo.get_active_iter()
        if tree_iter is None:
            return None
        model = self.device_combo.get_model()
        return model[tree_iter][1]  # BluetoothDevice

    def _reload_devices_for_selected_adapter(self, preferred_device_mac: str | None = None):
        adapter = self._get_selected_adapter()
        self.device_store.clear()
        self.devices = []

        if adapter is None:
            self.set_status("No adapter selected.")
            return

        self.devices = self.backend.list_devices(adapter)

        if not self.devices:
            self.set_status(f"No devices found for adapter {adapter.mac}.")
        else:
            self.set_status(f"Found {len(self.devices)} device(s) for adapter {adapter.mac}.")

        first_iter = None
        selected_iter = None
        for dev in self.devices:
            display = f"{dev.name} ({dev.mac})"
            iter_ = self.device_store.append([display, dev])
            if preferred_device_mac and dev.mac == preferred_device_mac:
                selected_iter = iter_
            if first_iter is None:
                first_iter = iter_

        if selected_iter is not None:
            self.device_combo.set_active_iter(selected_iter)
        elif first_iter is not None:
            self.device_combo.set_active_iter(first_iter)
        else:
            self.device_combo.set_active(-1)

    # ----- Callbacks -----

    def on_adapter_changed(self, combo: Gtk.ComboBox):
        self._reload_devices_for_selected_adapter()

    def on_refresh_clicked(self, button: Gtk.Button):
        prev_adapter = self._get_selected_adapter()
        prev_device = self._get_selected_device()
        prev_adapter_mac = prev_adapter.mac if prev_adapter else None
        prev_device_mac = prev_device.mac if prev_device else None

        self.adapters = self.backend.list_adapters()
        if not self.adapters:
            self.adapter_store.clear()
            self.device_store.clear()
            self.devices = []
            self.adapter_combo.set_active(-1)
            self.device_combo.set_active(-1)
            self.set_status("No Bluetooth adapters found in /var/lib/bluetooth.")
            self._show_error_dialog("No Bluetooth adapters found in /var/lib/bluetooth.")
            return

        self._populate_adapters(prev_adapter_mac, prev_device_mac)

    def on_export_clicked(self, button: Gtk.Button):
        adapter = self._get_selected_adapter()
        device = self._get_selected_device()
        if adapter is None:
            self._show_error_dialog("No adapter selected.")
            return
        if device is None:
            self._show_error_dialog("No device selected.")
            return

        # Pick default filename like "<device_name>-bt-key.json"
        default_name = f"{device.name}-bt-key.json".replace(" ", "_")

        dialog = Gtk.FileChooserDialog(
            title="Save Bluetooth key as JSON",
            parent=self,
            action=Gtk.FileChooserAction.SAVE,
        )
        dialog.add_buttons(
            Gtk.STOCK_CANCEL,
            Gtk.ResponseType.CANCEL,
            Gtk.STOCK_SAVE,
            Gtk.ResponseType.OK,
        )
        dialog.set_do_overwrite_confirmation(True)
        dialog.set_current_name(default_name)

        json_filter = Gtk.FileFilter()
        json_filter.set_name("JSON files")
        json_filter.add_pattern("*.json")
        dialog.add_filter(json_filter)

        any_filter = Gtk.FileFilter()
        any_filter.set_name("All files")
        any_filter.add_pattern("*")
        dialog.add_filter(any_filter)

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            filename = dialog.get_filename()
            dialog.destroy()
            try:
                record = self.backend.export_key(adapter, device)
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(record.to_dict(), f, indent=2)
                self.set_status(f"Exported key for {device.name} to {filename}")
                self._show_info_dialog(
                    f"Successfully exported key for {device.name}.\n\n"
                    f"File: {filename}",
                    title="Export successful",
                )
            except Exception as e:
                self._show_error_dialog(str(e), title="Export failed")
        else:
            dialog.destroy()

    def on_import_clicked(self, button: Gtk.Button):
        adapter = self._get_selected_adapter()
        device = self._get_selected_device()
        if adapter is None:
            self._show_error_dialog("No adapter selected.")
            return
        if device is None:
            self._show_error_dialog("No device selected.")
            return

        dialog = Gtk.FileChooserDialog(
            title="Select JSON file with Bluetooth key",
            parent=self,
            action=Gtk.FileChooserAction.OPEN,
        )
        dialog.add_buttons(
            Gtk.STOCK_CANCEL,
            Gtk.ResponseType.CANCEL,
            Gtk.STOCK_OPEN,
            Gtk.ResponseType.OK,
        )

        json_filter = Gtk.FileFilter()
        json_filter.set_name("JSON files")
        json_filter.add_pattern("*.json")
        dialog.add_filter(json_filter)

        any_filter = Gtk.FileFilter()
        any_filter.set_name("All files")
        any_filter.add_pattern("*")
        dialog.add_filter(any_filter)

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            filename = dialog.get_filename()
            dialog.destroy()
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    data = json.load(f)

                record = BtKeyRecord.from_dict(data)
                if record.adapter_mac != adapter.mac or record.device_mac != device.mac:
                    if not self._ask_yes_no(
                        (
                            "The selected adapter/device differ from the JSON file.\n\n"
                            f"Selected adapter: {adapter.mac}\n"
                            f"File adapter:     {record.adapter_mac}\n\n"
                            f"Selected device:  {device.mac}\n"
                            f"File device:      {record.device_mac}\n\n"
                            "Import using the adapter/device from the file?"
                        ),
                        title="Confirm adapter/device mismatch",
                    ):
                        return

                display_device = (
                    device.name if record.device_mac == device.mac else record.device_mac
                )

                result = self.backend.import_key(record)
                backup_path = result.backup_path if result else None
                backup_message = (
                    f" Timestamped JSON backup saved to: {backup_path}"
                    if backup_path
                    else ""
                )
                self.set_status(f"Imported key for {display_device}.{backup_message}")
                details = [
                    f"Successfully imported key for {display_device}.",
                    "You may need to restart Bluetooth:\n  sudo systemctl restart bluetooth",
                ]
                if backup_path:
                    details.insert(1, f"Backup saved to:\n{backup_path}\n")

                self._show_info_dialog(*details, title="Import successful")

                if self._ask_yes_no(
                    "Reload the Bluetooth service now to use the new key?",
                    title="Reload Bluetooth?",
                ):
                    success, detail = reload_bluetooth()
                    if success:
                        self.set_status(
                            f"Bluetooth service reloaded via: {detail}"
                        )
                        self._show_info_dialog(
                            "Bluetooth service was reloaded successfully.",
                            title="Bluetooth reloaded",
                        )
                    else:
                        self._show_error_dialog(
                            "Failed to reload Bluetooth automatically.\n\n"
                            f"Attempted: {detail}",
                            title="Reload failed",
                        )
            except json.JSONDecodeError as e:
                self._show_error_dialog(
                    f"Failed to parse JSON file: {e}", title="Import failed"
                )
            except ValueError as e:
                self._show_error_dialog(str(e), title="Import failed")
            except Exception as e:
                self._show_error_dialog(str(e), title="Import failed")
        else:
            dialog.destroy()


def main():
    # Basic OS check already done at import time, but just in case:
    if platform.system() != "Linux":
        print("This tool is intended for Linux (BlueZ).")
        return

    win = BtKeyGui()
    Gtk.main()


if __name__ == "__main__":
    main()
