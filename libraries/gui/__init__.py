"""Platform-specific Bluetooth GUI dispatchers."""
from __future__ import annotations

import platform
import sys


def run_platform_gui() -> None:
    """Launch the Bluetooth GUI for the current OS.

    On Linux this invokes the GTK-based interface, while on Windows it
    uses the Tkinter variant. Unsupported platforms will exit with a
    helpful message.
    """

    system = platform.system()
    if system == "Linux":
        from .linux import run_linux_gui

        run_linux_gui()
    elif system == "Windows":
        from .windows import run_windows_gui

        run_windows_gui()
    else:
        print(
            "This Bluetooth GUI currently supports Linux and Windows platforms only.",
            file=sys.stderr,
        )
        sys.exit(1)


__all__ = ["run_platform_gui"]
