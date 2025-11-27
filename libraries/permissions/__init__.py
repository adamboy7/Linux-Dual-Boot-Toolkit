"""Platform-aware permission helpers."""
from __future__ import annotations

import platform
from typing import Optional, Tuple


__all__ = ["ensure_platform_permissions", "get_platform_privileges"]


def get_platform_privileges(system_flag: Optional[str] = None) -> Tuple[bool, bool]:
    """Return ``(is_admin, is_system)`` for the current platform.

    Args:
        system_flag: Optional flag used on Windows to mark processes relaunched
            as SYSTEM. Ignored on other platforms.

    Returns:
        A tuple of booleans ``(is_admin, is_system)`` describing the current
        privilege level. On Linux, root implies both values are ``True``. On
        Windows, administrator rights set ``is_admin`` to ``True`` but
        ``is_system`` only becomes ``True`` when running as LocalSystem or when
        the provided ``system_flag`` is present in ``sys.argv``.
    """

    current_platform = platform.system()

    if current_platform == "Linux":
        from .linux import get_linux_privileges

        return get_linux_privileges()

    if current_platform == "Windows":
        from .windows import get_windows_privileges

        return get_windows_privileges(system_flag or "")

    return False, False


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
