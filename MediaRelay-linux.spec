# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

# GTK typelibs are NOT bundled here — gi reads them from the system path
# (/usr/lib/*/girepository-1.0/) at runtime, which is present on any system
# with GTK3 installed. Bundling them would require a runtime hook to redirect
# GI_TYPELIB_PATH, adding an extra file. The system path is always correct.

a = Analysis(
    ['Media-Sync.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('libraries/Media-Sync.ico', 'libraries'),
        *collect_data_files('gi'),
    ],
    hiddenimports=(
        collect_submodules('libraries')
        + [
            'gi',
            'gi.repository',
            'gi.repository.Gtk',
            'gi.repository.GLib',
            'gi.repository.GObject',
            'gi.repository.Gio',
            'gi.repository.Pango',
            'gi.repository.Atk',
            'gi.repository.AyatanaAppIndicator3',
            'gi.repository.AppIndicator3',
            'evdev',
            'evdev.ecodes',
        ]
    ),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['winrt', 'win32api', 'win32con', 'win32gui', 'pywintypes'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='MediaRelay-Linux',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
