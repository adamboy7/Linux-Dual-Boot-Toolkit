import sys
import time
import threading
import queue
from dataclasses import dataclass
import ctypes
import uuid

import numpy as np
import cv2

from PySide6.QtCore import Qt, QTimer, QRect
from PySide6.QtGui import QImage, QPixmap, QKeySequence, QShortcut
from PySide6.QtWidgets import QApplication, QLabel, QMainWindow, QWidget, QMessageBox


# ----------------------------
# Config (tune these)
# ----------------------------

VIDEO_DEVICE_NAME_HINT = "Razer Ripsaw"   # used for heuristics only (OpenCV index is still used)
AUDIO_DEVICE_NAME_HINT = "Ripsaw HD HDMI"   # name hint for the audio capture device to "listen" to

TARGET_WIDTH  = 1920
TARGET_HEIGHT = 1080
TARGET_FPS    = 60

PKEY_DEVICE_FRIENDLY_NAME = "{a45c254e-df1c-4efd-8020-67d146a850e0},14"


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def _ensure_winreg():
    try:
        import winreg  # type: ignore
    except ImportError as exc:
        raise OSError("winreg is only available on Windows.") from exc
    return winreg


@dataclass
class ListenState:
    enable_listen: int | None
    listen_device: str | None
    had_enable_listen: bool
    had_listen_device: bool


class WindowsListenManager:
    def __init__(self, device_name_hint: str):
        self.device_name_hint = device_name_hint
        self._original_state: ListenState | None = None
        self._capture_device_id: str | None = None
        self._default_render_device_id: str | None = None
        self._changed = False

    def apply(self, parent: QWidget | None = None) -> None:
        if not _is_windows():
            return
        try:
            self._capture_device_id = self._find_capture_device_id()
            if not self._capture_device_id:
                print("[Audio] No matching capture device found for listen-to-device setup.")
                return

            self._default_render_device_id = self._get_default_render_device_id()
            if not self._default_render_device_id:
                print("[Audio] No default playback device found for listen-to-device setup.")
                return

            state = self._read_listen_state()
            if not state:
                return
            self._original_state = state

            if state.enable_listen == 1:
                if (
                    state.listen_device
                    and self._default_render_device_id
                    and state.listen_device.lower() != self._default_render_device_id.lower()
                ):
                    self._maybe_switch_listen_device(parent, state.listen_device)
                return

            self._set_listen_state(enable_listen=1, listen_device=self._default_render_device_id)
            self._changed = True
            print("[Audio] Enabled listen-to-device and set default playback device.")
        except Exception as exc:
            print(f"[Audio] Listen-to-device setup failed: {exc}")

    def restore(self) -> None:
        if not (_is_windows() and self._changed and self._original_state and self._capture_device_id):
            return
        try:
            self._restore_listen_state()
        except Exception as exc:
            print(f"[Audio] Failed to restore listen-to-device settings: {exc}")

    def _maybe_switch_listen_device(self, parent: QWidget | None, current_device: str) -> None:
        if not self._default_render_device_id:
            return
        msg = (
            "Listen to this device is enabled but pointing to a non-default playback device.\n\n"
            "Switch listen playback to the default device?"
        )
        if QMessageBox.question(parent, "Switch listen device?", msg) != QMessageBox.Yes:
            return
        self._set_listen_state(enable_listen=1, listen_device=self._default_render_device_id)
        self._changed = True
        print(
            "[Audio] Updated listen-to-device playback device from "
            f"{current_device} to default."
        )

    def _find_capture_device_id(self) -> str | None:
        winreg = _ensure_winreg()
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as capture_root:
                index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(capture_root, index)
                    except OSError:
                        break
                    index += 1
                    friendly_name = self._read_capture_friendly_name(
                        winreg, f"{key_path}\\{subkey_name}"
                    )
                    if not friendly_name:
                        continue
                    if self.device_name_hint.lower() in friendly_name.lower():
                        return subkey_name
        except FileNotFoundError:
            return None
        return None

    @staticmethod
    def _read_capture_friendly_name(winreg, base_key: str) -> str | None:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{base_key}\\Properties") as props:
                value, _ = winreg.QueryValueEx(props, PKEY_DEVICE_FRIENDLY_NAME)
                return str(value)
        except OSError:
            return None

    def _read_listen_state(self) -> ListenState | None:
        winreg = _ensure_winreg()
        if not self._capture_device_id:
            return None
        key_path = rf"Software\Microsoft\Multimedia\Audio\Capture\{self._capture_device_id}"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                enable_listen, had_enable_listen = self._read_value(key, "EnableListen")
                listen_device, had_listen_device = self._read_value(key, "ListenDevice")
                return ListenState(
                    enable_listen=enable_listen,
                    listen_device=listen_device,
                    had_enable_listen=had_enable_listen,
                    had_listen_device=had_listen_device,
                )
        except FileNotFoundError:
            return ListenState(
                enable_listen=None,
                listen_device=None,
                had_enable_listen=False,
                had_listen_device=False,
            )

    @staticmethod
    def _read_value(key, name: str):
        try:
            value, _ = winreg.QueryValueEx(key, name)
            return value, True
        except OSError:
            return None, False

    def _set_listen_state(self, *, enable_listen: int, listen_device: str) -> None:
        winreg = _ensure_winreg()
        if not self._capture_device_id:
            return
        key_path = rf"Software\Microsoft\Multimedia\Audio\Capture\{self._capture_device_id}"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            winreg.SetValueEx(key, "EnableListen", 0, winreg.REG_DWORD, int(enable_listen))
            winreg.SetValueEx(key, "ListenDevice", 0, winreg.REG_SZ, str(listen_device))

    def _restore_listen_state(self) -> None:
        if not self._original_state or not self._capture_device_id:
            return
        winreg = _ensure_winreg()
        key_path = rf"Software\Microsoft\Multimedia\Audio\Capture\{self._capture_device_id}"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            self._restore_value(
                key,
                "EnableListen",
                self._original_state.enable_listen,
                winreg.REG_DWORD,
                self._original_state.had_enable_listen,
            )
            self._restore_value(
                key,
                "ListenDevice",
                self._original_state.listen_device,
                winreg.REG_SZ,
                self._original_state.had_listen_device,
            )
        print("[Audio] Restored listen-to-device settings.")

    @staticmethod
    def _restore_value(key, name: str, value, reg_type, had_value: bool) -> None:
        if had_value:
            winreg.SetValueEx(key, name, 0, reg_type, value)
        else:
            try:
                winreg.DeleteValue(key, name)
            except FileNotFoundError:
                pass

    @staticmethod
    def _get_default_render_device_id() -> str | None:
        if not _is_windows():
            return None

        CLSCTX_INPROC_SERVER = 1
        EDataFlow_render = 0
        ERole_multimedia = 1

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", ctypes.c_uint32),
                ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16),
                ("Data4", ctypes.c_ubyte * 8),
            ]

            def __init__(self, value: str):
                super().__init__()
                data = uuid.UUID(value).bytes_le
                self.Data1 = int.from_bytes(data[0:4], "little")
                self.Data2 = int.from_bytes(data[4:6], "little")
                self.Data3 = int.from_bytes(data[6:8], "little")
                self.Data4[:] = data[8:]

        class IMMDevice(ctypes.Structure):
            pass

        class IMMDeviceEnumerator(ctypes.Structure):
            pass

        HRESULT = ctypes.c_long

        IMMDeviceEnumerator_GetDefaultAudioEndpoint = ctypes.WINFUNCTYPE(
            HRESULT,
            ctypes.POINTER(IMMDeviceEnumerator),
            ctypes.c_int,
            ctypes.c_int,
            ctypes.POINTER(ctypes.POINTER(IMMDevice)),
        )

        IMMDevice_GetId = ctypes.WINFUNCTYPE(
            HRESULT, ctypes.POINTER(IMMDevice), ctypes.POINTER(ctypes.c_wchar_p)
        )

        class IMMDeviceEnumeratorVtbl(ctypes.Structure):
            _fields_ = [
                ("QueryInterface", ctypes.c_void_p),
                ("AddRef", ctypes.c_void_p),
                ("Release", ctypes.c_void_p),
                ("EnumAudioEndpoints", ctypes.c_void_p),
                ("GetDefaultAudioEndpoint", IMMDeviceEnumerator_GetDefaultAudioEndpoint),
                ("GetDevice", ctypes.c_void_p),
                ("RegisterEndpointNotificationCallback", ctypes.c_void_p),
                ("UnregisterEndpointNotificationCallback", ctypes.c_void_p),
            ]

        class IMMDeviceVtbl(ctypes.Structure):
            _fields_ = [
                ("QueryInterface", ctypes.c_void_p),
                ("AddRef", ctypes.c_void_p),
                ("Release", ctypes.c_void_p),
                ("Activate", ctypes.c_void_p),
                ("OpenPropertyStore", ctypes.c_void_p),
                ("GetId", IMMDevice_GetId),
                ("GetState", ctypes.c_void_p),
            ]

        IMMDeviceEnumerator._fields_ = [("lpVtbl", ctypes.POINTER(IMMDeviceEnumeratorVtbl))]
        IMMDevice._fields_ = [("lpVtbl", ctypes.POINTER(IMMDeviceVtbl))]

        CLSID_MMDeviceEnumerator = GUID("{BCDE0395-E52F-467C-8E3D-C4579291692E}")
        IID_IMMDeviceEnumerator = GUID("{A95664D2-9614-4F35-A746-DE8DB63617E6}")

        ole32 = ctypes.windll.ole32
        ole32.CoInitialize(None)
        device_id = None
        try:
            enumerator = ctypes.POINTER(IMMDeviceEnumerator)()
            hr = ole32.CoCreateInstance(
                ctypes.byref(CLSID_MMDeviceEnumerator),
                None,
                CLSCTX_INPROC_SERVER,
                ctypes.byref(IID_IMMDeviceEnumerator),
                ctypes.byref(enumerator),
            )
            if hr != 0:
                return None
            device = ctypes.POINTER(IMMDevice)()
            hr = enumerator.contents.lpVtbl.contents.GetDefaultAudioEndpoint(
                enumerator,
                EDataFlow_render,
                ERole_multimedia,
                ctypes.byref(device),
            )
            if hr != 0:
                return None
            id_ptr = ctypes.c_wchar_p()
            hr = device.contents.lpVtbl.contents.GetId(device, ctypes.byref(id_ptr))
            if hr != 0:
                return None
            device_id = id_ptr.value
            if id_ptr:
                ole32.CoTaskMemFree(id_ptr)
        finally:
            ole32.CoUninitialize()
        return device_id

@dataclass
class VideoMode:
    pip: bool = False
    pip_scale: float = 0.35   # PiP size relative to screen
    pip_margin: int = 24      # px margin from edges
    pip_corner: str = "br"    # "br", "bl", "tr", "tl"


class VideoCaptureThread(threading.Thread):
    """
    Captures frames with OpenCV (DirectShow) into a 1-deep queue to minimize latency.
    If capture falls behind, we drop old frames (always show newest).
    """

    def __init__(self, device_index: int):
        super().__init__(daemon=True)
        self.device_index = device_index
        self.frame_q = queue.Queue(maxsize=1)
        self.running = threading.Event()
        self.running.set()
        self._cap = None

    def _open(self):
        cap = cv2.VideoCapture(self.device_index, cv2.CAP_DSHOW)
        if not cap.isOpened():
            raise RuntimeError(f"Could not open video device index {self.device_index}")

        # Latency-critical knobs:
        # 1) Prefer MJPG if device supports it (reduces USB bandwidth, often lower overhead)
        try:
            cap.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc(*"MJPG"))
        except Exception:
            pass

        cap.set(cv2.CAP_PROP_FRAME_WIDTH,  TARGET_WIDTH)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, TARGET_HEIGHT)
        cap.set(cv2.CAP_PROP_FPS,          TARGET_FPS)

        # Best-effort: set buffer to 1 (not always honored)
        try:
            cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        except Exception:
            pass

        self._cap = cap

    def run(self):
        self._open()
        while self.running.is_set():
            ok, frame = self._cap.read()
            if not ok or frame is None:
                continue

            # Drop old frame if UI hasn't consumed it yet
            if self.frame_q.full():
                try:
                    _ = self.frame_q.get_nowait()
                except queue.Empty:
                    pass
            try:
                self.frame_q.put_nowait(frame)
            except queue.Full:
                pass

        try:
            if self._cap:
                self._cap.release()
        except Exception:
            pass

    def stop(self):
        self.running.clear()


class ViewerWindow(QMainWindow):
    def __init__(self, vid_thread: VideoCaptureThread, mode: VideoMode):
        super().__init__()
        self.vid_thread = vid_thread
        self.mode = mode

        self.setWindowTitle("KVM Viewer")
        self.setWindowFlags(
            Qt.FramelessWindowHint
            | Qt.Window
        )
        self.setCursor(Qt.ArrowCursor)

        self.label = QLabel(alignment=Qt.AlignCenter)
        self.label.setStyleSheet("background: black;")
        self.setCentralWidget(self.label)

        # Hotkeys
        QShortcut(QKeySequence("Esc"), self, activated=self.close)
        QShortcut(QKeySequence("F11"), self, activated=self.toggle_fullscreen)
        QShortcut(QKeySequence("P"), self, activated=self.toggle_pip)
        QShortcut(QKeySequence("1"), self, activated=lambda: self.set_corner("tl"))
        QShortcut(QKeySequence("2"), self, activated=lambda: self.set_corner("tr"))
        QShortcut(QKeySequence("3"), self, activated=lambda: self.set_corner("bl"))
        QShortcut(QKeySequence("4"), self, activated=lambda: self.set_corner("br"))

        # UI refresh timer (keep it modest; capture thread is already pulling at device rate)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_frame)
        self.timer.start(0)  # 0 = as fast as event loop can, typically fine

        self._fullscreen = False
        self.showFullScreen()
        self._fullscreen = True

    def set_corner(self, c: str):
        self.mode.pip_corner = c

    def toggle_pip(self):
        self.mode.pip = not self.mode.pip

    def toggle_fullscreen(self):
        if self._fullscreen:
            self.showNormal()
            self._fullscreen = False
        else:
            self.showFullScreen()
            self._fullscreen = True

    def _pip_geometry(self) -> QRect:
        screen = self.screen().availableGeometry()
        w = int(screen.width() * self.mode.pip_scale)
        h = int(screen.height() * self.mode.pip_scale)
        m = self.mode.pip_margin

        if self.mode.pip_corner == "tl":
            x, y = screen.left() + m, screen.top() + m
        elif self.mode.pip_corner == "tr":
            x, y = screen.right() - w - m, screen.top() + m
        elif self.mode.pip_corner == "bl":
            x, y = screen.left() + m, screen.bottom() - h - m
        else:  # "br"
            x, y = screen.right() - w - m, screen.bottom() - h - m

        return QRect(x, y, w, h)

    def update_frame(self):
        # Always use newest available frame
        frame = None
        try:
            frame = self.vid_thread.frame_q.get_nowait()
        except queue.Empty:
            return

        # Convert BGR -> RGB for Qt
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        h, w, ch = rgb.shape
        bytes_per_line = ch * w
        img = QImage(rgb.data, w, h, bytes_per_line, QImage.Format_RGB888)

        pix = QPixmap.fromImage(img)

        if self.mode.pip:
            # PiP: move window to corner, keep aspect
            self.setGeometry(self._pip_geometry())
        else:
            # Fullscreen: occupy screen
            # If you want borderless-but-not-fullscreen, use showMaximized() instead.
            if self._fullscreen:
                pass
            else:
                self.showMaximized()

        # Scale to label size without adding extra buffering
        self.label.setPixmap(pix.scaled(
            self.label.size(),
            Qt.KeepAspectRatio,
            Qt.FastTransformation
        ))

    def closeEvent(self, event):
        try:
            self.timer.stop()
        except Exception:
            pass
        super().closeEvent(event)


def pick_video_device_index_by_probe() -> int:
    """
    OpenCV can't reliably pick by name without extra libraries.
    We probe indices until we get frames. Then you can hardcode the index once known.
    """
    candidates = list(range(0, 10))
    for idx in candidates:
        cap = cv2.VideoCapture(idx, cv2.CAP_DSHOW)
        if not cap.isOpened():
            cap.release()
            continue
        cap.set(cv2.CAP_PROP_FRAME_WIDTH,  TARGET_WIDTH)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, TARGET_HEIGHT)
        cap.set(cv2.CAP_PROP_FPS,          TARGET_FPS)
        ok, frame = cap.read()
        cap.release()
        if ok and frame is not None:
            print(f"[Video] Using device index {idx}")
            return idx
    raise RuntimeError("Could not find a working video capture device (0-9).")


def main():
    # Pick device
    video_idx = pick_video_device_index_by_probe()

    # Start video capture thread
    vid_thread = VideoCaptureThread(video_idx)
    vid_thread.start()

    # Start UI
    app = QApplication(sys.argv)
    mode = VideoMode(pip=False)
    listen_manager = WindowsListenManager(AUDIO_DEVICE_NAME_HINT)
    win = ViewerWindow(vid_thread, mode)
    listen_manager.apply(parent=win)
    win.show()

    rc = app.exec()

    # Cleanup
    try:
        vid_thread.stop()
    except Exception:
        pass
    listen_manager.restore()

    return rc


if __name__ == "__main__":
    sys.exit(main())
