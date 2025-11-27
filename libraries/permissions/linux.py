"""Linux-specific permission helpers."""
from __future__ import annotations

import os
import platform
import shutil
import sys
from typing import Tuple


DISPLAY_ENV_VARS = (
    "DISPLAY",
    "XAUTHORITY",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
)


def ensure_root_linux() -> None:
    """Ensure the current process is running as root on Linux.

    If the host platform is not Linux or the effective UID is already 0, this
    function returns immediately. Otherwise, it attempts to relaunch the
    current script with elevated privileges via ``pkexec`` or ``sudo`` while
    preserving common display-related environment variables for GUI support.
    """

    if platform.system() != "Linux":
        return

    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        return

    script_path = os.path.abspath(sys.argv[0])
    args = [sys.executable, script_path, *sys.argv[1:]]

    display_env_vars = []
    for key in DISPLAY_ENV_VARS:
        value = os.environ.get(key)
        if value:
            display_env_vars.append(f"{key}={value}")

    if shutil.which("pkexec"):
        os.execvpe("pkexec", ["pkexec", "env", *display_env_vars, *args], os.environ)

    if shutil.which("sudo"):
        os.execvpe("sudo", ["sudo", "-E", *args], os.environ)

    sys.stderr.write("This tool must be run as root (pkexec/sudo not found).\n")
    sys.exit(1)


def get_linux_privileges() -> Tuple[bool, bool]:
    """Return ``(is_admin, is_system)`` for the current Linux process.

    Linux collapses administrator and system privileges into root; there is no
    higher context than UID 0. If the effective UID is 0, both values are
    ``True``. Otherwise, both are ``False`` because additional flags are
    unnecessary and cannot elevate a non-root process beyond its current level.
    """

    if platform.system() != "Linux":
        return False, False

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    return is_root, is_root
