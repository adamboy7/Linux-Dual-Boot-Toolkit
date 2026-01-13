from __future__ import annotations

import ctypes
import threading
from ctypes import wintypes

from .common import MediaSnapshot, State


def _load_gsmtc():
    try:
        from winrt.windows.media.control import (  # type: ignore
            GlobalSystemMediaTransportControlsSessionManager as GSMTCManager,
            GlobalSystemMediaTransportControlsSessionPlaybackStatus as PlaybackStatus,
        )
    except ModuleNotFoundError as exc:
        raise OSError("winrt is required for Windows media controls.") from exc
    return GSMTCManager, PlaybackStatus


class WindowsMediaController:
    async def snapshot(self) -> MediaSnapshot:
        gsmtc_manager, playback_status = _load_gsmtc()
        mgr = await gsmtc_manager.request_async()
        session = mgr.get_current_session()
        if session is None:
            return MediaSnapshot(State.NONE)

        playback = session.get_playback_info()
        status = playback.playback_status

        if status == playback_status.PLAYING:
            state = State.PLAYING
        elif status in (playback_status.PAUSED, playback_status.STOPPED):
            state = State.PAUSED
        else:
            state = State.PAUSED

        title = ""
        app = ""
        try:
            props = await session.try_get_media_properties_async()
            if props and props.title:
                title = props.title
        except Exception:
            pass
        try:
            app = session.source_app_user_model_id or ""
        except Exception:
            pass

        return MediaSnapshot(state, app=app, title=title)

    async def command(self, cmd: str) -> bool:
        gsmtc_manager, _ = _load_gsmtc()
        mgr = await gsmtc_manager.request_async()
        session = mgr.get_current_session()
        if session is None:
            return False
        try:
            if cmd == "play":
                return bool(await session.try_play_async())
            if cmd == "pause":
                return bool(await session.try_pause_async())
            if cmd == "stop":
                return bool(await session.try_stop_async())
        except Exception:
            return False
        return False


_user32 = ctypes.windll.user32
_kernel32 = ctypes.windll.kernel32
if not hasattr(wintypes, "ULONG_PTR"):
    wintypes.ULONG_PTR = (
        ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong
    )

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104
WM_QUIT = 0x0012
VK_MEDIA_STOP = 0xB2
VK_MEDIA_PLAY_PAUSE = 0xB3

_user32.CallNextHookEx.argtypes = (
    wintypes.HHOOK,
    ctypes.c_int,
    wintypes.WPARAM,
    wintypes.LPARAM,
)
_user32.CallNextHookEx.restype = ctypes.c_long


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", wintypes.ULONG_PTR),
    ]


LowLevelKeyboardProc = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM
)


class WindowsMediaKeyListener:
    def __init__(self, core: "RelayCore", swallow: bool = True):
        self._core = core
        self._swallow = swallow
        self._thread = None
        self._hook = None
        self._callback = None
        self._thread_id = None
        self._ready = threading.Event()
        self._stop_evt = threading.Event()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=2.0)

    def stop(self):
        self._stop_evt.set()
        if self._thread_id:
            _user32.PostThreadMessageW(self._thread_id, WM_QUIT, 0, 0)
        if self._thread:
            self._thread.join(timeout=2.0)

    def _handle_vk(self, vk_code: int) -> bool:
        if vk_code == VK_MEDIA_PLAY_PAUSE:
            self._core.ui_toggle()
            return True
        if vk_code == VK_MEDIA_STOP:
            self._core.ui_stop_all()
            return True
        return False

    def _run(self):
        self._thread_id = _kernel32.GetCurrentThreadId()

        def hook_proc(n_code, w_param, l_param):
            if n_code == 0 and w_param in (WM_KEYDOWN, WM_SYSKEYDOWN):
                info = ctypes.cast(l_param, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                if self._handle_vk(int(info.vkCode)):
                    if self._swallow:
                        return 1
            return _user32.CallNextHookEx(
                self._hook,
                n_code,
                wintypes.WPARAM(w_param),
                wintypes.LPARAM(l_param),
            )

        self._callback = LowLevelKeyboardProc(hook_proc)
        self._hook = _user32.SetWindowsHookExW(WH_KEYBOARD_LL, self._callback, None, 0)
        self._ready.set()

        msg = wintypes.MSG()
        while not self._stop_evt.is_set():
            result = _user32.GetMessageW(ctypes.byref(msg), 0, 0, 0)
            if result == 0:
                break
            if result == -1:
                break
            _user32.TranslateMessage(ctypes.byref(msg))
            _user32.DispatchMessageW(ctypes.byref(msg))

        if self._hook:
            _user32.UnhookWindowsHookEx(self._hook)
            self._hook = None
