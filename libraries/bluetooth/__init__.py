from __future__ import annotations

import platform

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

    if platform.system() == "Windows":
        return get_windows_bluetooth_adapters()

    return get_linux_bluetooth_adapters(base_dir=base_dir)


def get_devices_for_adapter(adapter):
    """Return devices paired to the given adapter using platform rules."""

    if platform.system() == "Windows":
        raw = adapter
        if isinstance(adapter, dict):
            raw = adapter.get("raw")
        if not isinstance(raw, str):
            raise TypeError("Expected adapter raw string or mapping with 'raw' key")
        return get_windows_devices_for_adapter(raw)

    if not isinstance(adapter, AdapterInfo):
        raise TypeError("Expected AdapterInfo for Linux adapters")

    return get_linux_devices_for_adapter(adapter)


__all__ = [
    "BASE_DIR",
    "AdapterInfo",
    "DeviceInfo",
    "WIN_BT_DEVICES_REG_PATH",
    "WIN_BT_KEYS_REG_PATH",
    "decode_bt_name",
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
