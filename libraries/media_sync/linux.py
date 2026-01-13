from __future__ import annotations

import importlib.util
import shutil
import subprocess
import threading
import time
from typing import Optional

from .common import MediaSnapshot, State
from ..permissions.linux import ensure_root_linux

EVDEV_AVAILABLE = importlib.util.find_spec("evdev") is not None
try:
    import evdev  # type: ignore
except ModuleNotFoundError:
    evdev = None
    EVDEV_AVAILABLE = False


class LinuxMediaController:
    def __init__(self):
        self._playerctl = shutil.which("playerctl")

    def _run_playerctl(self, *args: str) -> Optional[subprocess.CompletedProcess]:
        if not self._playerctl:
            return None
        result = subprocess.run(
            [self._playerctl, *args],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return None
        return result

    async def snapshot(self) -> MediaSnapshot:
        result = self._run_playerctl("status")
        if not result:
            return MediaSnapshot(State.NONE)

        status = result.stdout.strip().lower()
        if status == "playing":
            state = State.PLAYING
        elif status in ("paused", "stopped"):
            state = State.PAUSED
        else:
            state = State.NONE

        app = ""
        title = ""
        meta = self._run_playerctl("metadata", "--format", "{{playerName}}||{{title}}")
        if meta:
            parts = meta.stdout.strip().split("||", 1)
            if parts:
                app = parts[0].strip()
            if len(parts) > 1:
                title = parts[1].strip()

        return MediaSnapshot(state, app=app, title=title)

    async def command(self, cmd: str) -> bool:
        if cmd not in ("play", "pause", "stop"):
            return False
        result = self._run_playerctl(cmd)
        return result is not None


class LinuxMediaKeyListener:
    def __init__(self, core: "RelayCore", swallow: bool = True):
        self._core = core
        self._swallow = swallow
        self._thread = None
        self._stop_evt = threading.Event()
        self._devices = []
        self._uinputs = {}

    def start(self):
        if not EVDEV_AVAILABLE:
            return
        if self._swallow:
            ensure_root_linux()
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        for dev in self._devices:
            try:
                dev.ungrab()
            except Exception:
                pass
            try:
                dev.close()
            except Exception:
                pass
        for ui in self._uinputs.values():
            try:
                ui.close()
            except Exception:
                pass
        self._devices = []
        self._uinputs = {}

    def _handle_key(self, key_code: int) -> bool:
        if key_code == evdev.ecodes.KEY_PLAYPAUSE:
            self._core.ui_toggle()
            return True
        if key_code == evdev.ecodes.KEY_STOPCD:
            self._core.ui_stop_all()
            return True
        return False

    def _find_devices(self):
        devices = []
        for path in evdev.list_devices():
            try:
                dev = evdev.InputDevice(path)
            except Exception:
                continue
            try:
                caps = dev.capabilities().get(evdev.ecodes.EV_KEY, [])
            except Exception:
                dev.close()
                continue
            if (
                evdev.ecodes.KEY_PLAYPAUSE in caps
                or evdev.ecodes.KEY_STOPCD in caps
            ):
                devices.append(dev)
            else:
                dev.close()
        return devices

    def _setup_devices(self):
        if not self._swallow:
            return
        for dev in self._devices:
            try:
                dev.grab()
            except Exception:
                pass
            try:
                self._uinputs[dev.path] = evdev.UInput.from_device(
                    dev,
                    name=f"{dev.name} (MediaRelay)",
                )
            except Exception:
                pass

    def _teardown_device(self, dev):
        try:
            dev.ungrab()
        except Exception:
            pass
        try:
            dev.close()
        except Exception:
            pass
        ui = self._uinputs.pop(dev.path, None)
        if ui:
            try:
                ui.close()
            except Exception:
                pass

    def _forward_event(self, dev, event):
        ui = self._uinputs.get(dev.path)
        if not ui:
            return
        try:
            if (
                event.type == evdev.ecodes.EV_SYN
                and event.code == evdev.ecodes.SYN_REPORT
            ):
                ui.syn()
            else:
                ui.write_event(event)
        except Exception:
            pass

    def _run(self):
        self._devices = self._find_devices()
        self._setup_devices()

        while not self._stop_evt.is_set():
            if not self._devices:
                time.sleep(1.0)
                self._devices = self._find_devices()
                self._setup_devices()
                continue

            rlist, _, _ = evdev.util.select(self._devices, [], [], 0.5)
            for dev in rlist:
                try:
                    for event in dev.read():
                        swallow_event = False
                        if event.type == evdev.ecodes.EV_KEY:
                            if event.code in (
                                evdev.ecodes.KEY_PLAYPAUSE,
                                evdev.ecodes.KEY_STOPCD,
                            ):
                                if event.value == 1:
                                    self._handle_key(event.code)
                                if self._swallow:
                                    swallow_event = True
                        if self._swallow and not swallow_event:
                            self._forward_event(dev, event)
                except OSError:
                    self._teardown_device(dev)
                    if dev in self._devices:
                        self._devices.remove(dev)
