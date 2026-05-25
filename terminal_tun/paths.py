from __future__ import annotations

import os
import sys
from pathlib import Path


APP_NAME = "terminal-tun"


def config_dir() -> Path:
    override = os.environ.get("TERMINAL_TUN_HOME")
    if override:
        return Path(override).expanduser()

    if sys.platform.startswith("win"):
        root = os.environ.get("APPDATA")
        if root:
            return Path(root) / APP_NAME

    root = os.environ.get("XDG_CONFIG_HOME")
    if root:
        return Path(root) / APP_NAME
    return Path.home() / ".config" / APP_NAME


def data_dir() -> Path:
    override = os.environ.get("TERMINAL_TUN_DATA")
    if override:
        return Path(override).expanduser()

    if sys.platform.startswith("win"):
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if root:
            return Path(root) / APP_NAME

    root = os.environ.get("XDG_DATA_HOME")
    if root:
        return Path(root) / APP_NAME
    return Path.home() / ".local" / "share" / APP_NAME


def state_path() -> Path:
    return config_dir() / "state.json"


def generated_config_path() -> Path:
    return config_dir() / "sing-box.json"


def bin_dir() -> Path:
    return data_dir() / "bin"
