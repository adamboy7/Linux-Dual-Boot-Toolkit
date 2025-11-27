from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from typing import Protocol

from ..bt_gui_logic import BtKeyRecord, save_timestamped_backup
from .common import BASE_DIR, normalize_mac
from .linux import (
    AdapterInfo,
    DeviceInfo,
    export_bt_key,
    get_linux_bluetooth_adapters,
    get_linux_devices_for_adapter,
    import_bt_key,
)
from .windows import (
    format_mac,
    get_windows_bluetooth_adapters,
    get_windows_devices_for_adapter,
    read_device_key_hex,
)
from .windows_registry import backup_windows_bluetooth_registry


@dataclass
class BluetoothAdapter:
    mac: str
    name: str
    is_default: bool = False
    data: object | None = None


@dataclass
class BluetoothDevice:
    mac: str
    name: str
    data: object | None = None


@dataclass
class ImportResult:
    backup_path: str | None = None
    registry_backups: dict[str, str] | None = None


class BluetoothBackend(Protocol):
    def list_adapters(self) -> list[BluetoothAdapter]: ...

    def list_devices(self, adapter: BluetoothAdapter) -> list[BluetoothDevice]: ...

    def export_key(
        self, adapter: BluetoothAdapter, device: BluetoothDevice
    ) -> BtKeyRecord: ...

    def import_key(self, record: BtKeyRecord) -> ImportResult | None: ...


class LinuxBluetoothBackend:
    def __init__(self, *, base_dir: str = BASE_DIR):
        self.base_dir = base_dir

    def list_adapters(self) -> list[BluetoothAdapter]:
        adapters: list[BluetoothAdapter] = []
        for adapter in get_linux_bluetooth_adapters(base_dir=self.base_dir):
            adapters.append(
                BluetoothAdapter(
                    mac=adapter.mac,
                    name=adapter.name,
                    is_default=adapter.is_default,
                    data=adapter,
                )
            )
        return adapters

    def list_devices(self, adapter: BluetoothAdapter) -> list[BluetoothDevice]:
        if not isinstance(adapter.data, AdapterInfo):
            raise TypeError("Expected a BluetoothAdapter wrapping AdapterInfo for Linux")

        devices: list[BluetoothDevice] = []
        for device in get_linux_devices_for_adapter(adapter.data):
            devices.append(BluetoothDevice(mac=device.mac, name=device.name, data=device))
        return devices

    def export_key(
        self, adapter: BluetoothAdapter, device: BluetoothDevice
    ) -> BtKeyRecord:
        return export_bt_key(adapter.mac, device.mac, base_dir=self.base_dir)

    def import_key(self, record: BtKeyRecord) -> ImportResult | None:
        backup_path = import_bt_key(record, base_dir=self.base_dir)
        return ImportResult(backup_path=backup_path)


class WindowsBluetoothBackend:
    @staticmethod
    def _sanitize_mac(raw: str) -> str:
        return normalize_mac(raw).replace(":", "").replace("-", "").lower()

    def _adapter_raw(self, adapter: BluetoothAdapter) -> str:
        if isinstance(adapter.data, dict) and "raw" in adapter.data:
            return str(adapter.data["raw"])
        return self._sanitize_mac(adapter.mac)

    def _device_raw(self, device: BluetoothDevice) -> str:
        if isinstance(device.data, dict) and "raw" in device.data:
            return str(device.data["raw"])
        return self._sanitize_mac(device.mac)

    def list_adapters(self) -> list[BluetoothAdapter]:
        adapters: list[BluetoothAdapter] = []
        for adapter in get_windows_bluetooth_adapters():
            adapters.append(
                BluetoothAdapter(
                    mac=adapter.get("mac", ""),
                    name=adapter.get("name", adapter.get("mac", "")),
                    data=adapter,
                )
            )
        return adapters

    def list_devices(self, adapter: BluetoothAdapter) -> list[BluetoothDevice]:
        adapter_raw = self._adapter_raw(adapter)
        devices: list[BluetoothDevice] = []
        for device in get_windows_devices_for_adapter(adapter_raw):
            devices.append(
                BluetoothDevice(
                    mac=device.get("mac", ""),
                    name=device.get("name", device.get("mac", "")),
                    data=device,
                )
            )
        return devices

    def export_key(
        self, adapter: BluetoothAdapter, device: BluetoothDevice
    ) -> BtKeyRecord:
        adapter_raw = self._adapter_raw(adapter)
        device_raw = self._device_raw(device)
        key_hex = read_device_key_hex(adapter_raw, device_raw)
        return BtKeyRecord(
            adapter_mac=format_mac(adapter_raw),
            device_mac=format_mac(device_raw),
            key_hex=key_hex,
        )

    def import_key(self, record: BtKeyRecord) -> ImportResult | None:
        import winreg

        adapter_raw = self._sanitize_mac(record.adapter_mac)
        device_raw = self._sanitize_mac(record.device_mac)
        key_bytes = bytes.fromhex(record.key_hex)

        key_path = f"{WIN_BT_KEYS_REG_PATH}\\{adapter_raw}"

        previous_value: bytes | bytearray | None = None
        previous_value_type: int | None = None
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ
            ) as adap_key:
                try:
                    prev_value, prev_type = winreg.QueryValueEx(adap_key, device_raw)
                    if isinstance(prev_value, (bytes, bytearray)):
                        previous_value = prev_value
                        previous_value_type = prev_type
                except FileNotFoundError:
                    pass
        except FileNotFoundError:
            pass

        backup_record = record
        if isinstance(previous_value, (bytes, bytearray)):
            backup_record = BtKeyRecord(
                adapter_mac=record.adapter_mac,
                device_mac=record.device_mac,
                key_hex=bytes(previous_value).hex().upper(),
            )

        backup_path = save_timestamped_backup(backup_record, directory=os.getcwd())
        registry_backups = backup_windows_bluetooth_registry(directory=os.getcwd())

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE
        ) as adap_key:
            winreg.SetValueEx(
                adap_key, device_raw, 0, winreg.REG_BINARY, key_bytes
            )

        return ImportResult(backup_path=backup_path, registry_backups=registry_backups)


def get_bluetooth_backend(*, base_dir: str = BASE_DIR) -> BluetoothBackend:
    if platform.system() == "Windows":
        return WindowsBluetoothBackend()
    return LinuxBluetoothBackend(base_dir=base_dir)


__all__ = [
    "BluetoothAdapter",
    "BluetoothBackend",
    "BluetoothDevice",
    "ImportResult",
    "LinuxBluetoothBackend",
    "WindowsBluetoothBackend",
    "get_bluetooth_backend",
]
