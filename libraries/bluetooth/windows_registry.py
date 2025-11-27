from __future__ import annotations

import os
import platform
import subprocess
from datetime import datetime

from .windows import WIN_BT_DEVICES_REG_PATH, WIN_BT_KEYS_REG_PATH


def _require_windows():
    if platform.system() != "Windows":
        raise OSError("This helper is only available on Windows.")


def _reg_export(relative_path: str, destination: str) -> str:
    """Export an HKLM registry subtree to ``destination``."""

    _require_windows()
    abs_dest = os.path.abspath(destination)
    command = ["reg", "export", f"HKLM\\{relative_path}", abs_dest, "/y"]
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise RuntimeError(
            f"Failed to export registry path HKLM\\{relative_path} to {abs_dest}: "
            f"{stderr or result.returncode}"
        )
    return abs_dest


def _reg_import(backup_file: str) -> None:
    """Import a ``.reg`` backup file using the native ``reg`` utility."""

    _require_windows()
    command = ["reg", "import", os.path.abspath(backup_file)]
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise RuntimeError(
            f"Failed to import registry backup {backup_file}: {stderr or result.returncode}"
        )


def backup_windows_bluetooth_registry(directory: str = ".") -> dict[str, str]:
    """Export Bluetooth "Devices" and "Keys" registry trees to ``.reg`` files."""

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backups: dict[str, str] = {}
    for label, reg_path in (
        ("keys", WIN_BT_KEYS_REG_PATH),
        ("devices", WIN_BT_DEVICES_REG_PATH),
    ):
        filename = f"bt_registry_backup_{label}_{timestamp}.reg"
        destination = os.path.join(directory or ".", filename)
        backups[label] = _reg_export(reg_path, destination)
    return backups


def restore_windows_bluetooth_registry(backups: dict[str, str]) -> None:
    """Restore registry backups exported by :func:`backup_windows_bluetooth_registry`."""

    errors: list[str] = []
    for label, path in backups.items():
        try:
            _reg_import(path)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{label}: {exc}")

    if errors:
        raise RuntimeError("; ".join(errors))


__all__ = [
    "backup_windows_bluetooth_registry",
    "restore_windows_bluetooth_registry",
]
