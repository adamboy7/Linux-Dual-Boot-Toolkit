import sys
import time
import threading
import queue
from dataclasses import dataclass

import numpy as np
import cv2

from PySide6.QtCore import Qt, QTimer, QRect
from PySide6.QtGui import QImage, QPixmap, QIcon, QAction
from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QInputDialog,
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

@dataclass
class VideoMode:
    pip: bool = False
    pip_scale: float = 0.25   # PiP size relative to screen
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
        if self.mode.pip:
            if self._fullscreen or self.isMaximized() or self.isFullScreen():
                self.showNormal()
                self._fullscreen = False

    def toggle_fullscreen(self):
        if self._fullscreen:
            self.showNormal()
            self._fullscreen = False
        else:
            self.mode.pip = False
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
            if self._fullscreen or self.isMaximized() or self.isFullScreen():
                self.showNormal()
                self._fullscreen = False
            pip_rect = self._pip_geometry()
            self.resize(pip_rect.size())
            self.move(pip_rect.topLeft())
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


class TrayController:
    def __init__(self, app: QApplication, window: ViewerWindow, mode: VideoMode):
        self.app = app
        self.window = window
        self.mode = mode

        self.tray = QSystemTrayIcon(self._build_icon(), self.window)
        self.menu = QMenu()

        self.show_action = QAction("Show Viewer", self.menu)
        self.show_action.triggered.connect(self._show_viewer)
        self.menu.addAction(self.show_action)

        self.fullscreen_action = QAction("Fullscreen", self.menu, checkable=True)
        self.fullscreen_action.triggered.connect(self._toggle_fullscreen)
        self.menu.addAction(self.fullscreen_action)

        self.pip_action = QAction("Picture-in-Picture", self.menu, checkable=True)
        self.pip_action.triggered.connect(self._toggle_pip)
        self.menu.addAction(self.pip_action)

        self.corner_menu = QMenu("PiP Corner", self.menu)
        self._add_corner_action("Top Left", "tl")
        self._add_corner_action("Top Right", "tr")
        self._add_corner_action("Bottom Left", "bl")
        self._add_corner_action("Bottom Right", "br")
        self.menu.addMenu(self.corner_menu)

        self.pip_scale_action = QAction("PiP Scale...", self.menu)
        self.pip_scale_action.triggered.connect(self._set_pip_scale)
        self.menu.addAction(self.pip_scale_action)

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

    def _toggle_pip(self):
        self.window.toggle_pip()
        self.sync_state()

    def _set_corner(self, corner: str):
        self.window.set_corner(corner)
        self.sync_state()

    def _add_corner_action(self, label: str, corner: str):
        action = QAction(label, self.corner_menu)
        action.triggered.connect(lambda checked=False, c=corner: self._set_corner(c))
        self.corner_menu.addAction(action)

    def _set_pip_scale(self):
        current_percent = int(round(self.mode.pip_scale * 100))
        text, ok = QInputDialog.getText(
            self.window,
            "Set PiP Scale",
            "Enter PiP scale (%):",
            text=f"{current_percent}",
        )
        if not ok:
            return
        cleaned = text.strip().replace("%", "")
        try:
            percent = float(cleaned)
        except ValueError:
            return
        if percent <= 0:
            return
        percent = min(percent, 100.0)
        self.mode.pip_scale = percent / 100.0

    def _exit_app(self):
        self.window.close()
        self.app.quit()

    def sync_state(self):
        self.fullscreen_action.setChecked(self.window._fullscreen)
        self.pip_action.setChecked(self.mode.pip)


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
    win = ViewerWindow(vid_thread, mode)
    TrayController(app, win, mode)
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
