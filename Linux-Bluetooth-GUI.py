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

import os
import sys
import re
import json
import shutil
import tempfile
import subprocess
import platform
from dataclasses import dataclass

def ensure_root():
    """Ensure the process is running as root, attempting to re-exec if needed."""

    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        return

    script_path = os.path.abspath(sys.argv[0])
    args = [sys.executable, script_path, *sys.argv[1:]]

    display_env_vars = []
    for key in ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
        value = os.environ.get(key)
        if value:
            display_env_vars.append(f"{key}={value}")

    if shutil.which("pkexec"):
        os.execvpe("pkexec", ["pkexec", "env", *display_env_vars, *args], os.environ)

    if shutil.which("sudo"):
        os.execvpe("sudo", ["sudo", "-E", *args], os.environ)

    sys.stderr.write("This tool must be run as root (pkexec/sudo not found).\n")
    sys.exit(1)


# Only import GTK if on Linux
if platform.system() == "Linux":
    ensure_root()
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk
else:
    print("This GUI tool currently only supports Linux (BlueZ).")
    sys.exit(1)

BASE_DIR = "/var/lib/bluetooth"


@dataclass
class BtKeyRecord:
    adapter_mac: str   # AA:BB:CC:DD:EE:FF
    device_mac: str    # 11:22:33:44:55:66
    key_hex: str       # e.g., 32 hex chars

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
        expected_len = 32  # BlueZ link keys are 16 bytes (32 hex chars)
        if len(key_hex_clean) != expected_len:
            raise ValueError(
                f"key_hex must be a {expected_len}-character hex string (got {len(key_hex_clean)} characters)."
            )
        if not re.fullmatch(r"[0-9A-Fa-f]+", key_hex_clean):
            raise ValueError("key_hex must contain only hexadecimal characters (0-9, A-F).")

        return cls(
            adapter_mac=adapter_mac,
            device_mac=device_mac,
            key_hex=key_hex_clean.upper(),
        )


@dataclass
class AdapterInfo:
    mac: str
    name: str
    is_default: bool
    path: str


@dataclass
class DeviceInfo:
    mac: str
    name: str
    info_path: str


def normalize_mac_colon(mac: str) -> str:
    """Normalize MAC to AA:BB:CC:DD:EE:FF."""
    mac = mac.strip().replace("-", ":").upper()
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC address: {mac}")
    return ":".join(f"{int(p, 16):02X}" for p in parts)


def is_mac_dir_name(name: str) -> bool:
    """True if name looks like a MAC address dir (AA:BB:CC:DD:EE:FF)."""
    return re.fullmatch(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}", name) is not None

def get_adapters_from_bluetoothctl() -> dict:
    """
    Parse `bluetoothctl list` to get names and default flag for controllers.

    Returns:
        {
          "AA:BB:CC:DD:EE:FF": {"name": "MyHost", "is_default": True/False},
          ...
        }
    """
    mapping = {}
    try:
        out = subprocess.check_output(
            ["bluetoothctl", "list"], text=True, stderr=subprocess.DEVNULL
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return mapping

    for line in out.splitlines():
        line = line.strip()
        if not line or not line.startswith("Controller "):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        # Controller MAC Name [default]
        mac_raw = parts[1]
        try:
            mac_norm = normalize_mac_colon(mac_raw)
        except ValueError:
            continue

        # Name is everything after the MAC up to any [bracketed] token
        name_tokens = []
        for token in parts[2:]:
            if token.startswith("[") and token.endswith("]"):
                break
            name_tokens.append(token)
        name = " ".join(name_tokens) if name_tokens else mac_norm

        is_default = "[default]" in line

        mapping[mac_norm] = {
            "name": name,
            "is_default": is_default,
        }

    return mapping


def read_key_from_info(info_path: str) -> str:
    """Read Key=... from a BlueZ info file."""
    with open(info_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip().startswith("Key="):
                return line.strip().split("=", 1)[1].strip()
    raise RuntimeError(f"No 'Key=' entry found in {info_path}")


def linux_export_key(adapter_mac: str, device_mac: str) -> BtKeyRecord:
    adapter_mac = normalize_mac_colon(adapter_mac)
    device_mac = normalize_mac_colon(device_mac)
    info_path = os.path.join(BASE_DIR, adapter_mac, device_mac, "info")

    if not os.path.isfile(info_path):
        raise FileNotFoundError(
            f"BlueZ info file not found at {info_path}. "
            "Is the device paired on this Linux install?"
        )

    key_hex = read_key_from_info(info_path).upper()
    return BtKeyRecord(adapter_mac=adapter_mac, device_mac=device_mac, key_hex=key_hex)


def linux_import_key(record: BtKeyRecord):
    adapter_mac = normalize_mac_colon(record.adapter_mac)
    device_mac = normalize_mac_colon(record.device_mac)
    info_path = os.path.join(BASE_DIR, adapter_mac, device_mac, "info")

    if not os.path.isfile(info_path):
        raise FileNotFoundError(
            f"BlueZ info file not found at {info_path}. "
            "Make sure the device is paired once in Linux so this file exists."
        )

    # Backup first
    backup_path = info_path + ".bak"
    shutil.copy2(info_path, backup_path)

    # Read all lines and replace/insert Key=...
    with open(info_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    replaced = False
    for line in lines:
        if line.strip().startswith("Key=") and not replaced:
            new_lines.append(f"Key={record.key_hex}\n")
            replaced = True
        else:
            new_lines.append(line)

    if not replaced:
        # Insert into [LinkKey] section if present; else append
        output_lines = []
        inserted = False
        in_linkkey = False
        for line in new_lines:
            stripped = line.strip()
            output_lines.append(line)
            if stripped == "[LinkKey]":
                in_linkkey = True
            elif stripped.startswith("[") and stripped.endswith("]") and in_linkkey:
                # Leaving [LinkKey]; insert before this section
                output_lines.insert(len(output_lines) - 1, f"Key={record.key_hex}\n")
                inserted = True
                in_linkkey = False

        if not inserted:
            output_lines.append("\n[LinkKey]\n")
            output_lines.append(f"Key={record.key_hex}\n")

        new_lines = output_lines

    temp_path = None
    try:
        fd, temp_path = tempfile.mkstemp(
            prefix="info.", suffix=".tmp", dir=os.path.dirname(info_path)
        )
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
            tmp_file.writelines(new_lines)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())

        os.replace(temp_path, info_path)
    except Exception as exc:  # noqa: BLE001
        try:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
        finally:
            try:
                shutil.copy2(backup_path, info_path)
            except Exception:  # noqa: BLE001
                pass
        raise RuntimeError(f"Failed to update BlueZ info file: {exc}") from exc

    return backup_path


def restart_bluetooth_service() -> tuple[bool, str]:
    """Attempt to restart the Bluetooth service. Returns (success, detail)."""

    commands = [
        (["systemctl", "restart", "bluetooth"], "systemctl restart bluetooth"),
        (["service", "bluetooth", "restart"], "service bluetooth restart"),
    ]

    errors: list[str] = []

    for cmd, label in commands:
        try:
            subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return True, label
        except FileNotFoundError:
            errors.append(f"{label}: command not found")
        except subprocess.CalledProcessError as e:
            stderr = (e.stderr or "").strip()
            errors.append(f"{label}: {stderr or e}")

    return False, "; ".join(errors)


def find_adapters() -> list[AdapterInfo]:
    adapters: list[AdapterInfo] = []
    if not os.path.isdir(BASE_DIR):
        return adapters

    btctl_map = get_adapters_from_bluetoothctl()

    for entry in os.listdir(BASE_DIR):
        full_path = os.path.join(BASE_DIR, entry)
        if not os.path.isdir(full_path):
            continue
        if not is_mac_dir_name(entry):
            continue

        mac = normalize_mac_colon(entry)

        # Start with MAC as fallback name
        name = mac
        is_default = False

        # Prefer data from bluetoothctl list (name + [default])
        if mac in btctl_map:
            name = btctl_map[mac]["name"] or mac
            is_default = btctl_map[mac]["is_default"]

        # If bluetoothctl didn't give us a name, try settings file
        if name == mac:
            settings_path = os.path.join(full_path, "settings")
            if os.path.isfile(settings_path):
                try:
                    with open(settings_path, "r", encoding="utf-8") as f:
                        for line in f:
                            if line.startswith("Name="):
                                name_val = line.split("=", 1)[1].strip()
                                if name_val:
                                    name = name_val
                                break
                except Exception:
                    pass

        adapters.append(AdapterInfo(mac=mac, name=name, is_default=is_default, path=full_path))

    # If none marked default (e.g. bluetoothctl missing), mark the first one as default
    if adapters and not any(a.is_default for a in adapters):
        adapters[0].is_default = True

    return adapters



def find_devices(adapter: AdapterInfo) -> list[DeviceInfo]:
    devices: list[DeviceInfo] = []
    if not os.path.isdir(adapter.path):
        return devices

    for entry in os.listdir(adapter.path):
        full_path = os.path.join(adapter.path, entry)
        if not os.path.isdir(full_path):
            continue
        if not is_mac_dir_name(entry):
            continue
        info_path = os.path.join(full_path, "info")
        if not os.path.isfile(info_path):
            continue

        mac = normalize_mac_colon(entry)
        name = mac
        try:
            with open(info_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("Name="):
                        n = line.split("=", 1)[1].strip()
                        if n:
                            name = n
                        break
        except Exception:
            pass

        devices.append(DeviceInfo(mac=mac, name=name, info_path=info_path))

    return devices


class BtKeyGui(Gtk.Window):
    def __init__(self):
        super().__init__(title="Bluetooth Key Sync (Linux)")
        self.set_border_width(10)
        self.set_default_size(480, 200)

        # Data
        self.adapters: list[AdapterInfo] = find_adapters()
        self.devices: list[DeviceInfo] = []

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

        self.adapter_store = Gtk.ListStore(str, object)  # display_text, AdapterInfo
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

        self.device_store = Gtk.ListStore(str, object)  # display_text, DeviceInfo
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

        self.restore_button = Gtk.Button(label="Restore backup…")
        self.restore_button.connect("clicked", self.on_restore_clicked)
        button_box.pack_start(self.restore_button, True, True, 0)

        # Status row with refresh button on the right
        status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        vbox.pack_start(status_box, False, False, 4)

        self.status_label = Gtk.Label(label="")
        self.status_label.set_xalign(0.0)
        status_box.pack_start(self.status_label, True, True, 0)

        self.refresh_button = Gtk.Button(label="Refresh")
        self.refresh_button.connect("clicked", self.on_refresh_clicked)
        status_box.pack_start(self.refresh_button, False, False, 0)

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

    def _show_info_dialog(self, message: str, title: str = "Info"):
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

    def _get_selected_adapter(self) -> AdapterInfo | None:
        tree_iter = self.adapter_combo.get_active_iter()
        if tree_iter is None:
            return None
        model = self.adapter_combo.get_model()
        return model[tree_iter][1]  # AdapterInfo

    def _get_selected_device(self) -> DeviceInfo | None:
        tree_iter = self.device_combo.get_active_iter()
        if tree_iter is None:
            return None
        model = self.device_combo.get_model()
        return model[tree_iter][1]  # DeviceInfo

    def _reload_devices_for_selected_adapter(self, preferred_device_mac: str | None = None):
        adapter = self._get_selected_adapter()
        self.device_store.clear()
        self.devices = []

        if adapter is None:
            self.set_status("No adapter selected.")
            return

        self.devices = find_devices(adapter)

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

        self.adapters = find_adapters()
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
                record = linux_export_key(adapter.mac, device.mac)
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
                # Use the key from file, but force current adapter + device
                record.adapter_mac = adapter.mac
                record.device_mac = device.mac

                backup_path = linux_import_key(record)
                self.set_status(
                    f"Imported key for {device.name}. Backup created: {backup_path}"
                )
                self._show_info_dialog(
                    f"Successfully imported key for {device.name}.\n\n"
                    f"Original info file was backed up as:\n{backup_path}\n\n"
                    f"You may need to restart Bluetooth:\n"
                    f"  sudo systemctl restart bluetooth",
                    title="Import successful",
                )

                if self._ask_yes_no(
                    "Reload the Bluetooth service now to use the new key?",
                    title="Reload Bluetooth?",
                ):
                    success, detail = restart_bluetooth_service()
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

    def on_restore_clicked(self, button: Gtk.Button):
        adapter = self._get_selected_adapter()
        device = self._get_selected_device()

        if adapter is None:
            self._show_error_dialog("No adapter selected.")
            return
        if device is None:
            self._show_error_dialog("No device selected.")
            return

        info_path = device.info_path
        backup_path = info_path + ".bak"

        if not os.path.isfile(info_path):
            self._show_error_dialog(
                f"BlueZ info file not found at {info_path}.\n"
                "Make sure the device has been paired once in Linux.",
                title="Restore failed",
            )
            return

        if not os.path.isfile(backup_path):
            self._show_error_dialog(
                f"No backup file found for this device. Expected:\n{backup_path}",
                title="Restore failed",
            )
            return

        if not self._ask_yes_no(
            f"Restore backup for {device.name}?\n\n"
            f"This will overwrite the current info file with:\n{backup_path}",
            title="Restore backup?",
        ):
            return

        try:
            shutil.copy2(backup_path, info_path)
        except Exception as e:  # noqa: BLE001
            self._show_error_dialog(str(e), title="Restore failed")
            return

        self.set_status(f"Restored backup for {device.name} to {info_path}")
        self._show_info_dialog(
            f"Successfully restored backup for {device.name}.\n\n"
            f"Backup file: {backup_path}\n"
            f"Restored to: {info_path}",
            title="Restore successful",
        )


def main():
    # Basic OS check already done at import time, but just in case:
    if platform.system() != "Linux":
        print("This tool is intended for Linux (BlueZ).")
        return

    win = BtKeyGui()
    Gtk.main()


if __name__ == "__main__":
    main()
