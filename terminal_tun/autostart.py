from __future__ import annotations

import os
import platform
import shlex
import subprocess
import sys
from pathlib import Path

from .errors import TerminalTunError


SERVICE_NAME = "terminal-tun"


def install_autostart(system: bool = False) -> Path:
    current = platform.system().lower()
    if current == "windows":
        return _install_windows(system=system)
    if current == "linux":
        return _install_linux(system=system)
    raise TerminalTunError(f"Autostart is not implemented for {current}")


def remove_autostart(system: bool = False) -> Path:
    current = platform.system().lower()
    if current == "windows":
        return _remove_windows(system=system)
    if current == "linux":
        return _remove_linux(system=system)
    raise TerminalTunError(f"Autostart is not implemented for {current}")


def autostart_status(system: bool = False) -> str:
    current = platform.system().lower()
    if current == "windows":
        path = _windows_startup_script()
        return f"installed: {path}" if path.exists() else "not installed"
    if current == "linux":
        path = _linux_service_path(system)
        return f"installed: {path}" if path.exists() else "not installed"
    return f"not implemented for {current}"


def _module_command() -> list[str]:
    return [sys.executable, "-m", "terminal_tun", "run"]


def _install_windows(system: bool) -> Path:
    command = [sys.executable, "-m", "terminal_tun", "background", "start"]
    if system:
        task_command = " ".join(_windows_quote(part) for part in command)
        result = subprocess.run(
            [
                "schtasks",
                "/Create",
                "/TN",
                SERVICE_NAME,
                "/SC",
                "ONLOGON",
                "/TR",
                task_command,
                "/RL",
                "HIGHEST",
                "/F",
            ]
        )
        if result.returncode != 0:
            raise TerminalTunError("Failed to create scheduled task. Try running the terminal as Administrator.")
        return Path(f"Scheduled Task: {SERVICE_NAME}")

    path = _windows_startup_script()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "@echo off\r\n"
        f'start "{SERVICE_NAME}" /min {_windows_quote(command[0])} -m terminal_tun background start\r\n',
        encoding="utf-8",
    )
    return path


def _remove_windows(system: bool) -> Path:
    if system:
        subprocess.run(["schtasks", "/Delete", "/TN", SERVICE_NAME, "/F"])
        return Path(f"Scheduled Task: {SERVICE_NAME}")
    path = _windows_startup_script()
    if path.exists():
        path.unlink()
    return path


def _install_linux(system: bool) -> Path:
    path = _linux_service_path(system)
    path.parent.mkdir(parents=True, exist_ok=True)
    command = " ".join(shlex.quote(part) for part in _module_command())
    wanted_by = "multi-user.target" if system else "default.target"
    path.write_text(
        "[Unit]\n"
        "Description=terminal-tun sing-box manager\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        f"ExecStart={command}\n"
        "Restart=always\n"
        "RestartSec=3\n\n"
        "[Install]\n"
        f"WantedBy={wanted_by}\n",
        encoding="utf-8",
    )
    if system:
        subprocess.run(["systemctl", "daemon-reload"])
        result = subprocess.run(["systemctl", "enable", "--now", SERVICE_NAME])
    else:
        subprocess.run(["systemctl", "--user", "daemon-reload"])
        result = subprocess.run(["systemctl", "--user", "enable", "--now", SERVICE_NAME])
    if result.returncode != 0:
        raise TerminalTunError("Service file was written, but systemctl could not enable it.")
    return path


def _remove_linux(system: bool) -> Path:
    path = _linux_service_path(system)
    if system:
        subprocess.run(["systemctl", "disable", "--now", SERVICE_NAME])
    else:
        subprocess.run(["systemctl", "--user", "disable", "--now", SERVICE_NAME])
    if path.exists():
        path.unlink()
    if system:
        subprocess.run(["systemctl", "daemon-reload"])
    else:
        subprocess.run(["systemctl", "--user", "daemon-reload"])
    return path


def _windows_startup_script() -> Path:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise TerminalTunError("APPDATA is not set.")
    return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "terminal-tun.cmd"


def _linux_service_path(system: bool) -> Path:
    if system:
        return Path("/etc/systemd/system") / f"{SERVICE_NAME}.service"
    return Path.home() / ".config" / "systemd" / "user" / f"{SERVICE_NAME}.service"


def _windows_quote(value: str) -> str:
    return f'"{value}"' if " " in value or "\t" in value else value
