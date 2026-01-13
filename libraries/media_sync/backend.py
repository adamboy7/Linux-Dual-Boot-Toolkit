from __future__ import annotations

import sys


def build_media_controller():
    if sys.platform == "win32":
        from .windows import WindowsMediaController

        return WindowsMediaController()
    from .linux import LinuxMediaController

    return LinuxMediaController()


def build_media_key_listener(core: "RelayCore", swallow: bool):
    if sys.platform == "win32":
        from .windows import WindowsMediaKeyListener

        return WindowsMediaKeyListener(core, swallow=swallow)
    from .linux import LinuxMediaKeyListener

    return LinuxMediaKeyListener(core, swallow=swallow)
