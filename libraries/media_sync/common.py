from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class State(str, Enum):
    NONE = "none"  # No controllable session
    PAUSED = "paused"  # Session exists but not playing
    PLAYING = "playing"  # Session playing


class ResumeMode(str, Enum):
    HOST_ONLY = "host_only"
    CLIENT_ONLY = "client_only"
    BLIND = "blind"


@dataclass
class MediaSnapshot:
    state: State
    app: str = ""
    title: str = ""
