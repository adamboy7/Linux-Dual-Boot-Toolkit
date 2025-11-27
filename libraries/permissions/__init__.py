"""Platform-aware permission helpers."""
from __future__ import annotations

import platform
from typing import Optional


__all__ = ["ensure_platform_permissions"]


def ensure_platform_permissions(system_flag: Optional[str] = None) -> None:
    """Ensure the process has the right privileges for the current platform.

    * On Linux, this enforces root via :func:`permissions.linux.ensure_root_linux`.
    * On Windows, this enforces a SYSTEM token via
      :func:`permissions.windows.ensure_windows_system`.

    Args:
        system_flag: Optional flag passed through to ``ensure_windows_system``
            to detect a re-launched SYSTEM instance.
    """

    current_platform = platform.system()

    if current_platform == "Linux":
        from .linux import ensure_root_linux

        ensure_root_linux()
    elif current_platform == "Windows":
        from .windows import ensure_windows_system

        ensure_windows_system(system_flag or "")
