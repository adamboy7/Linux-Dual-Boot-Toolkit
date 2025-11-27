"""Deprecated combined Bluetooth utilities module.

This module now re-exports helpers from :mod:`libraries.bluetooth` for
backwards compatibility. Please update imports to use the new
platform-specific package layout.
"""
from __future__ import annotations

import warnings

from . import bluetooth
from .bluetooth import *  # noqa: F401,F403

warnings.warn(
    "libraries.bluetooth_utils is deprecated; import from libraries.bluetooth instead.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = bluetooth.__all__
