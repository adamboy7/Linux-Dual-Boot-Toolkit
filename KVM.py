import sys
import threading
import queue

import numpy as np
import cv2

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QImage, QPixmap, QIcon, QAction
from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QMenu,
    QSystemTrayIcon,
    QWidget,
)


# ----------------------------
# Config (tune these)
# ----------------------------

VIDEO_DEVICE_NAME_HINT = "Razer Ripsaw"   # used for heuristics only (OpenCV index is still used)

TARGET_WIDTH  = 1920
TARGET_HEIGHT = 1080
TARGET_FPS    = 60

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
    def __init__(self, vid_thread: VideoCaptureThread):
        super().__init__()
        self.vid_thread = vid_thread

        self.setWindowTitle("KVM Viewer")
        self.setWindowFlags(
            Qt.FramelessWindowHint
            | Qt.Window
        )
        self.setCursor(Qt.ArrowCursor)

        self.label = QLabel(alignment=Qt.AlignCenter)
        self.label.setStyleSheet("background: black;")
        self.setCentralWidget(self.label)

        # UI refresh timer (keep it modest; capture thread is already pulling at device rate)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_frame)
        self.timer.start(0)  # 0 = as fast as event loop can, typically fine

        self._fullscreen = False
        self.showFullScreen()
        self._fullscreen = True

    def set_fullscreen(self, enabled: bool):
        if enabled:
            self.showFullScreen()
            self._fullscreen = True
        else:
            self.showNormal()
            self._fullscreen = False

    def toggle_fullscreen(self):
        self.set_fullscreen(not self._fullscreen)

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

        # Fullscreen: occupy screen
        # If you want borderless-but-not-fullscreen, use showMaximized() instead.
        if self._fullscreen:
            pass
        else:
            self.showMaximized()

        self.label.setPixmap(pix)

    def closeEvent(self, event):
        try:
            self.timer.stop()
        except Exception:
            pass
        super().closeEvent(event)


class TrayController:
    def __init__(self, app: QApplication, window: ViewerWindow):
        self.app = app
        self.window = window

        self.tray = QSystemTrayIcon(self._build_icon(), self.window)
        self.menu = QMenu()

        self.show_action = QAction("Show Viewer", self.menu)
        self.show_action.triggered.connect(self._show_viewer)
        self.menu.addAction(self.show_action)

        self.fullscreen_action = QAction("Fullscreen", self.menu, checkable=True)
        self.fullscreen_action.triggered.connect(self._toggle_fullscreen)
        self.menu.addAction(self.fullscreen_action)

        self.menu.addSeparator()

        self.exit_action = QAction("Exit", self.menu)
        self.exit_action.triggered.connect(self._exit_app)
        self.menu.addAction(self.exit_action)

        self.tray.setContextMenu(self.menu)
        self.tray.activated.connect(self._tray_activated)
        self.sync_state()
        self.tray.show()

    def _build_icon(self) -> QIcon:
        icon = QIcon.fromTheme("video-display")
        if not icon.isNull():
            return icon
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.black)
        return QIcon(pixmap)

    def _show_viewer(self):
        self.window.show()
        self.window.raise_()
        self.window.activateWindow()

    def _tray_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self._show_viewer()

    def _toggle_fullscreen(self):
        self.window.toggle_fullscreen()
        self.sync_state()

    def _exit_app(self):
        self.tray.hide()
        self.window.close()
        self.app.exit(0)

    def sync_state(self):
        self.fullscreen_action.setChecked(self.window._fullscreen)


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
    win = ViewerWindow(vid_thread)
    TrayController(app, win)
    win.show()

    rc = app.exec()

    # Cleanup
    try:
        vid_thread.stop()
    except Exception:
        pass

    return rc


if __name__ == "__main__":
    sys.exit(main())
