from __future__ import annotations

import os
import platform
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from .core import check_config, find_core
from .errors import TerminalTunError
from .paths import log_path, pid_path
from .singbox import write_config


def start_background(state: dict[str, Any], extra_args: list[str] | None = None) -> tuple[int, Path, Path]:
    existing = _read_pid()
    if existing and _is_running(existing):
        raise TerminalTunError(f"VPN is already running in background (pid {existing}).")

    config_path = write_config(state)
    core_path = find_core(state)
    if check_config(core_path, config_path) != 0:
        raise TerminalTunError("Generated config did not pass sing-box check.")

    log_file = log_path()
    log_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file = pid_path()
    pid_file.parent.mkdir(parents=True, exist_ok=True)

    command = [str(core_path), "run", "-c", str(config_path)]
    if extra_args:
        command.extend(extra_args)

    with log_file.open("ab") as log:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            close_fds=not _is_windows(),
            creationflags=_windows_creation_flags(),
            startupinfo=_windows_startupinfo(),
        )

    time.sleep(0.5)
    if process.poll() is not None:
        raise TerminalTunError(f"sing-box exited immediately with code {process.returncode}. Check log: {log_file}")

    pid_file.write_text(str(process.pid), encoding="utf-8")
    return process.pid, config_path, log_file


def stop_background() -> int:
    pid = _read_pid()
    if not pid:
        raise TerminalTunError("VPN background process is not running.")
    if not _is_running(pid):
        _clear_pid()
        raise TerminalTunError(f"Saved pid {pid} is not running anymore.")

    if _is_windows():
        result = subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode != 0 and _is_running(pid):
            raise TerminalTunError(f"Failed to stop background process {pid}.")
    else:
        os.kill(pid, signal.SIGTERM)
        deadline = time.time() + 5
        while time.time() < deadline:
            if not _is_running(pid):
                break
            time.sleep(0.2)
        if _is_running(pid):
            os.kill(pid, signal.SIGKILL)

    _clear_pid()
    return pid


def background_status() -> tuple[bool, int | None, Path, Path]:
    pid = _read_pid()
    if pid and _is_running(pid):
        return True, pid, pid_path(), log_path()
    if pid:
        _clear_pid()
    return False, None, pid_path(), log_path()


def _read_pid() -> int | None:
    path = pid_path()
    if not path.exists():
        return None
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except ValueError:
        _clear_pid()
        return None


def _clear_pid() -> None:
    path = pid_path()
    if path.exists():
        path.unlink()


def _is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if _is_windows():
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return result.returncode == 0 and str(pid) in result.stdout
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _windows_creation_flags() -> int:
    if not _is_windows():
        return 0
    flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    flags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return flags


def _windows_startupinfo() -> subprocess.STARTUPINFO | None:
    if not _is_windows():
        return None
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return startupinfo
