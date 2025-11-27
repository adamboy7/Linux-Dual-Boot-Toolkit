"""Windows-specific permission helpers."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Optional


def get_windows_username() -> str:
    """Get the Windows account name from the current token using GetUserNameW."""

    import ctypes
    from ctypes import wintypes

    GetUserNameW = ctypes.windll.advapi32.GetUserNameW
    GetUserNameW.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]

    size = wintypes.DWORD(0)
    GetUserNameW(None, ctypes.byref(size))
    buf = ctypes.create_unicode_buffer(size.value)
    if not GetUserNameW(buf, ctypes.byref(size)):
        return os.environ.get("USERNAME", "")
    return buf.value


def is_system() -> bool:
    """Return True if the current token belongs to LocalSystem."""

    return get_windows_username().upper() == "SYSTEM"


def is_admin() -> bool:
    """Return True if the process token has administrator privileges."""

    import ctypes

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> None:
    """Relaunch this script with UAC elevation, then exit the current process."""

    import ctypes

    script = os.path.abspath(sys.argv[0])
    params = " ".join(f'"{arg}"' for arg in [script] + sys.argv[1:])

    rc = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        None,
        1,
    )

    if int(rc) <= 32:
        from tkinter import messagebox

        messagebox.showerror(
            "Elevation failed",
            "Could not elevate to administrator.\n\n" f"Return code: {rc}",
        )
    sys.exit(0)


def relaunch_as_system_via_psexec(
    system_flag: str, additional_args: Optional[list[str]] = None
) -> None:
    """From an elevated admin process, relaunch this script as SYSTEM using PsExec."""

    import tkinter.messagebox as messagebox

    script = os.path.abspath(sys.argv[0])
    extra_args = additional_args or []

    psexec_path = (
        shutil.which("psexec")
        or shutil.which("PsExec64.exe")
        or shutil.which("PsExec.exe")
    )

    if not psexec_path:
        base_dir = os.path.dirname(script)
        for fn in ("PsExec64.exe", "PsExec.exe", "psexec.exe"):
            candidate = os.path.join(base_dir, fn)
            if os.path.isfile(candidate):
                psexec_path = candidate
                break

    if not psexec_path:
        messagebox.showerror(
            "PsExec not found",
            "Unable to locate PsExec.\n\nMake sure PsExec is either in PATH or in the same folder as this script.",
        )
        sys.exit(1)

    args = [psexec_path, "-accepteula", "-i", "-s", sys.executable, script, system_flag]
    args.extend(a for a in sys.argv[1:] if a != system_flag)
    args.extend(extra_args)

    try:
        subprocess.Popen(args, close_fds=True)
    except Exception as exc:
        messagebox.showerror(
            "PsExec launch failed", f"Failed to start SYSTEM instance via PsExec:\n\n{exc}"
        )
        sys.exit(1)

    sys.exit(0)


def ensure_windows_system(system_flag: str) -> None:
    """Ensure the process runs with SYSTEM privileges, re-launching if needed."""

    if system_flag in sys.argv or is_system():
        return

    if not is_admin():
        relaunch_as_admin()
        return

    relaunch_as_system_via_psexec(system_flag)
