from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from .errors import TerminalTunError
from .paths import bin_dir


RELEASES_API = "https://api.github.com/repos/SagerNet/sing-box/releases"


def find_core(state: dict[str, Any]) -> Path:
    configured = state.get("core", {}).get("path")
    if configured:
        path = Path(configured).expanduser()
        if path.exists():
            return path
        raise TerminalTunError(f"Configured sing-box path does not exist: {path}")

    env_path = os.environ.get("SING_BOX_PATH")
    if env_path:
        path = Path(env_path).expanduser()
        if path.exists():
            return path
        raise TerminalTunError(f"SING_BOX_PATH does not exist: {path}")

    found = shutil.which("sing-box")
    if found:
        return Path(found)

    bundled = bin_dir() / ("sing-box.exe" if platform.system().lower() == "windows" else "sing-box")
    if bundled.exists():
        return bundled

    raise TerminalTunError("sing-box was not found. Run `terminal-tun core install` or set `terminal-tun core path`.")


def install_core(version: str = "latest") -> Path:
    release = _release(version)
    asset = _select_asset(release)
    download_url = asset["browser_download_url"]
    target_dir = bin_dir()
    target_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="terminal-tun-") as tmp_name:
        tmp_dir = Path(tmp_name)
        archive = tmp_dir / asset["name"]
        _download(download_url, archive)
        extracted = tmp_dir / "extract"
        extracted.mkdir()
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(extracted)
        else:
            with tarfile.open(archive) as tf:
                tf.extractall(extracted)

        binary_name = "sing-box.exe" if platform.system().lower() == "windows" else "sing-box"
        binaries = [path for path in extracted.rglob(binary_name) if path.is_file()]
        if not binaries:
            raise TerminalTunError(f"Downloaded archive did not contain {binary_name}")
        target = target_dir / binary_name
        shutil.copy2(binaries[0], target)
        if not platform.system().lower().startswith("win"):
            target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return target


def run_core(core_path: Path, config_path: Path, extra_args: list[str] | None = None) -> int:
    command = [str(core_path), "run", "-c", str(config_path)]
    if extra_args:
        command.extend(extra_args)
    try:
        return subprocess.run(command).returncode
    except KeyboardInterrupt:
        return 130


def check_config(core_path: Path, config_path: Path) -> int:
    return subprocess.run([str(core_path), "check", "-c", str(config_path)]).returncode


def _release(version: str) -> dict[str, Any]:
    url = f"{RELEASES_API}/latest" if version == "latest" else f"{RELEASES_API}/tags/{version}"
    request = urllib.request.Request(url, headers={"User-Agent": "terminal-tun/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # pragma: no cover - network dependent
        raise TerminalTunError(f"Failed to query sing-box releases: {exc}") from exc


def _select_asset(release: dict[str, Any]) -> dict[str, Any]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    os_name = {
        "windows": "windows",
        "linux": "linux",
        "darwin": "darwin",
    }.get(system)
    arch = _arch(machine)
    if not os_name or not arch:
        raise TerminalTunError(f"Unsupported platform for automatic install: {system}/{machine}")

    ext = ".zip" if os_name == "windows" else ".tar.gz"
    expected = f"{os_name}-{arch}"
    candidates = []
    for asset in release.get("assets", []):
        name = asset.get("name", "")
        if expected in name and name.endswith(ext) and f"{arch}v" not in name:
            candidates.append(asset)
    if not candidates:
        raise TerminalTunError(f"No sing-box release asset found for {expected}{ext}")
    return candidates[0]


def _arch(machine: str) -> str | None:
    if machine in {"x86_64", "amd64"}:
        return "amd64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    if machine.startswith("armv7"):
        return "armv7"
    if machine in {"i386", "i686", "x86"}:
        return "386"
    return None


def _download(url: str, path: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "terminal-tun/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response, path.open("wb") as fh:
            shutil.copyfileobj(response, fh)
    except Exception as exc:  # pragma: no cover - network dependent
        raise TerminalTunError(f"Failed to download {url}: {exc}") from exc
