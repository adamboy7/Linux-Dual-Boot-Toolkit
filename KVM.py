import sys
import time
import threading
import queue
from dataclasses import dataclass

import numpy as np
import cv2
import sounddevice as sd

from PySide6.QtCore import Qt, QTimer, QRect
from PySide6.QtGui import QImage, QPixmap, QKeySequence, QShortcut
from PySide6.QtWidgets import QApplication, QLabel, QMainWindow, QWidget


# ----------------------------
# Config (tune these)
# ----------------------------

VIDEO_DEVICE_NAME_HINT = "Razer Ripsaw"   # used for heuristics only (OpenCV index is still used)
AUDIO_DEVICE_NAME_HINT = "Razer Ripsaw"   # used to pick input device for sounddevice

TARGET_WIDTH  = 1920
TARGET_HEIGHT = 1080
TARGET_FPS    = 60

# Audio: smaller = lower latency, but more likely crackle if system can't keep up
AUDIO_SAMPLERATE = 48000
AUDIO_CHANNELS   = 2
# Lower blocksize/queue = lower latency, but too small can crackle on weak systems.
AUDIO_BLOCKSIZE  = 96      # try 64 / 96 / 128
AUDIO_QUEUE_MAX  = 3       # small queue prevents latency ballooning
USE_WASAPI_EXCLUSIVE = True


@dataclass
class VideoMode:
    pip: bool = False
    pip_scale: float = 0.35   # PiP size relative to screen
    pip_margin: int = 24      # px margin from edges
    pip_corner: str = "br"    # "br", "bl", "tr", "tl"


class LowLatencyAudioLoopback:
    """
    Input: capture card audio device
    Output: Windows default output device (sounddevice default)
    Uses callback streams + tiny queue to keep latency minimal.
    """

    def __init__(self, input_device_index: int | None):
        self.input_device_index = input_device_index
        self._q = queue.Queue(maxsize=AUDIO_QUEUE_MAX)
        self._running = False
        self._in_stream = None
        self._out_stream = None

    def _in_cb(self, indata, frames, time_info, status):
        if status:
            # Over/under-runs show up here (useful while tuning blocksize)
            # print("AUDIO IN:", status)
            pass
        try:
            self._q.put_nowait(indata.copy())
        except queue.Full:
            # Drop oldest so we keep the newest audio (minimizes latency).
            try:
                _ = self._q.get_nowait()
                self._q.put_nowait(indata.copy())
            except queue.Empty:
                pass

    def _out_cb(self, outdata, frames, time_info, status):
        if status:
            # print("AUDIO OUT:", status)
            pass
        try:
            data = self._q.get_nowait()
            # Ensure shape matches out buffer
            if data.shape != outdata.shape:
                outdata.fill(0)
                n = min(len(data), len(outdata))
                outdata[:n] = data[:n]
            else:
                outdata[:] = data
        except queue.Empty:
            outdata.fill(0)

    def start(self):
        if self._running:
            return
        self._running = True

        extra_settings = None
        if USE_WASAPI_EXCLUSIVE and sys.platform == "win32":
            try:
                extra_settings = sd.WasapiSettings(exclusive=True)
            except Exception:
                extra_settings = None

        # Default output device = None (sounddevice uses OS default output)
        # For lowest latency, ask for 'low' latency; actual depends on device/driver.
        try:
            self._in_stream = sd.InputStream(
                device=self.input_device_index,
                samplerate=AUDIO_SAMPLERATE,
                channels=AUDIO_CHANNELS,
                blocksize=AUDIO_BLOCKSIZE,
                latency="low",
                dtype="float32",
                extra_settings=extra_settings,
                callback=self._in_cb,
            )
            self._out_stream = sd.OutputStream(
                device=None,  # default output
                samplerate=AUDIO_SAMPLERATE,
                channels=AUDIO_CHANNELS,
                blocksize=AUDIO_BLOCKSIZE,
                latency="low",
                dtype="float32",
                extra_settings=extra_settings,
                callback=self._out_cb,
            )
        except Exception:
            # Fallback to shared-mode if exclusive mode fails.
            self._in_stream = sd.InputStream(
                device=self.input_device_index,
                samplerate=AUDIO_SAMPLERATE,
                channels=AUDIO_CHANNELS,
                blocksize=AUDIO_BLOCKSIZE,
                latency="low",
                dtype="float32",
                callback=self._in_cb,
            )
            self._out_stream = sd.OutputStream(
                device=None,  # default output
                samplerate=AUDIO_SAMPLERATE,
                channels=AUDIO_CHANNELS,
                blocksize=AUDIO_BLOCKSIZE,
                latency="low",
                dtype="float32",
                callback=self._out_cb,
            )

        self._in_stream.start()
        self._out_stream.start()

    def stop(self):
        self._running = False
        for s in (self._in_stream, self._out_stream):
            try:
                if s:
                    s.stop()
                    s.close()
            except Exception:
                pass
        self._in_stream = None
        self._out_stream = None


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


def pick_audio_input_device_index(name_hint: str) -> int | None:
    """
    Choose the first input device whose name contains name_hint.
    Returns None if not found (you'll get default input, which is not ideal).
    """
    devices = sd.query_devices()
    for i, d in enumerate(devices):
        if d.get("max_input_channels", 0) >= 1:
            nm = (d.get("name") or "")
            if name_hint.lower() in nm.lower():
                return i
    return None


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
    # Pick devices
    audio_in = pick_audio_input_device_index(AUDIO_DEVICE_NAME_HINT)
    if audio_in is None:
        print("[Audio] Could not find capture card audio by name; using default input (not recommended).")
    else:
        print(f"[Audio] Using input device index {audio_in}: {sd.query_devices(audio_in)['name']}")

    video_idx = pick_video_device_index_by_probe()

    # Start video capture thread
    vid_thread = VideoCaptureThread(video_idx)
    vid_thread.start()

    # Start audio loopback
    audio = LowLatencyAudioLoopback(audio_in)
    audio.start()

    # Start UI
    app = QApplication(sys.argv)
    mode = VideoMode(pip=False)
    win = ViewerWindow(vid_thread, mode)
    win.show()

    rc = app.exec()

    # Cleanup
    try:
        audio.stop()
    except Exception:
        pass
    try:
        vid_thread.stop()
    except Exception:
        pass

    return rc


if __name__ == "__main__":
    sys.exit(main())
