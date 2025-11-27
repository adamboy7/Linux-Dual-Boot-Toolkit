from __future__ import annotations

from .backend import (
    BluetoothAdapter,
    BluetoothBackend,
    BluetoothDevice,
    ImportResult,
    LinuxBluetoothBackend,
    WindowsBluetoothBackend,
    get_bluetooth_backend,
)
from .common import (
    BASE_DIR,
    format_mac,
    is_mac_dir_name,
    normalize_mac,
    normalize_mac_colon,
    reload_bluetooth,
)
from .linux import (
    AdapterInfo,
    DeviceInfo,
    export_bt_key,
    find_adapters,
    get_adapters_from_bluetoothctl,
    get_linux_bluetooth_adapters,
    get_linux_devices_for_adapter,
    import_bt_key,
    read_key_from_info,
)
from .windows import (
    WIN_BT_DEVICES_REG_PATH,
    WIN_BT_KEYS_REG_PATH,
    decode_bt_name,
    get_device_display_name,
    get_windows_bluetooth_adapters,
    get_windows_devices_for_adapter,
    read_device_key_hex,
)
from .windows_registry import (
    backup_windows_bluetooth_registry,
    restore_windows_bluetooth_registry,
)


def get_bluetooth_adapters(*, base_dir: str = BASE_DIR):
    """Return Bluetooth adapters using platform-specific discovery."""

    backend = get_bluetooth_backend(base_dir=base_dir)
    return backend.list_adapters()


def get_devices_for_adapter(adapter):
    """Return devices paired to the given adapter using platform rules."""

    backend = get_bluetooth_backend()
    return backend.list_devices(adapter)


__all__ = [
    "BluetoothAdapter",
    "BluetoothBackend",
    "BluetoothDevice",
    "LinuxBluetoothBackend",
    "WindowsBluetoothBackend",
    "BASE_DIR",
    "AdapterInfo",
    "DeviceInfo",
    "WIN_BT_DEVICES_REG_PATH",
    "WIN_BT_KEYS_REG_PATH",
    "decode_bt_name",
    "get_bluetooth_backend",
    "ImportResult",
    "backup_windows_bluetooth_registry",
    "export_bt_key",
    "find_adapters",
    "format_mac",
    "get_adapters_from_bluetoothctl",
    "get_bluetooth_adapters",
    "get_devices_for_adapter",
    "get_device_display_name",
    "get_linux_bluetooth_adapters",
    "get_linux_devices_for_adapter",
    "get_windows_bluetooth_adapters",
    "get_windows_devices_for_adapter",
    "import_bt_key",
    "is_mac_dir_name",
    "normalize_mac",
    "normalize_mac_colon",
    "read_device_key_hex",
    "restore_windows_bluetooth_registry",
    "read_key_from_info",
    "reload_bluetooth",
]
