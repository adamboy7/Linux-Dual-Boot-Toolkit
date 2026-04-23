#!/usr/bin/env python3
"""Updates the Linux Dual-Boot Toolkit to the latest version."""
from __future__ import annotations

import io
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError

REPO_ZIP_URL = "https://github.com/adamboy7/Linux-Dual-Boot-Toolkit/archive/refs/heads/main.zip"
ZIP_PREFIX = "Linux-Dual-Boot-Toolkit-main/"


def log(msg: str) -> None:
    print(msg)


def find_toolkit_root() -> Path:
    return Path(__file__).resolve().parent


def has_git() -> bool:
    try:
        subprocess.run(["git", "--version"], check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def update_via_git(root: Path) -> bool:
    if not (root / ".git").exists():
        return False
    if not has_git():
        return False
    log("[INFO] Git repository detected. Running git pull...")
    try:
        result = subprocess.run(
            ["git", "pull", "origin", "main"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            log(f"[INFO] {result.stdout.strip()}")
            log("[INFO] Update complete.")
            return True
        log(f"[WARN] git pull failed: {result.stderr.strip()}")
        return False
    except Exception as e:
        log(f"[WARN] git pull error: {e}")
        return False


def update_via_zip(root: Path) -> bool:
    log("[INFO] Downloading latest version from GitHub...")
    try:
        with urlopen(REPO_ZIP_URL, timeout=30) as response:
            data = response.read()
    except URLError as e:
        log(f"[ERROR] Download failed: {e}")
        return False

    log("[INFO] Extracting...")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for member in zf.namelist():
                if not member.startswith(ZIP_PREFIX):
                    continue
                relative = member[len(ZIP_PREFIX):]
                if not relative:
                    continue
                target = root / relative
                if member.endswith("/"):
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as src:
                        target.write_bytes(src.read())
    except Exception as e:
        log(f"[ERROR] Extraction failed: {e}")
        return False

    log("[INFO] Update complete.")
    return True


def main() -> None:
    root = find_toolkit_root()
    log(f"[INFO] Toolkit root: {root}")

    if update_via_git(root):
        return

    log("[INFO] Falling back to ZIP download...")
    if not update_via_zip(root):
        sys.exit(1)


if __name__ == "__main__":
    main()
