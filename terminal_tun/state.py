from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import TerminalTunError
from .paths import state_path


STATE_VERSION = 1

DEFAULT_STATE: dict[str, Any] = {
    "version": STATE_VERSION,
    "mode": "rules",
    "selected_outbound": None,
    "active_profile": None,
    "subscriptions": {},
    "outbounds": {},
    "profiles": {},
    "rules": {
        "domains": [],
        "domain_suffixes": [],
        "domain_keywords": [],
        "process_names": [],
        "process_paths": [],
    },
    "routing": {
        "block_quic": True,
        "reject_windows_delivery_optimization": True,
    },
    "tun": {
        "enabled": True,
        "interface_name": "terminaltun0",
        "address": "172.28.0.1/30",
        "mtu": 9000,
        "strict_route": True,
    },
    "mixed": {
        "enabled": True,
        "listen": "127.0.0.1",
        "listen_port": 2080,
    },
    "urltest": {
        "enabled": True,
        "tag": "auto",
        "url": "https://www.gstatic.com/generate_204",
        "interval": "3m",
        "tolerance": 50,
    },
    "core": {
        "path": None,
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_state() -> dict[str, Any]:
    path = state_path()
    if not path.exists():
        state = copy.deepcopy(DEFAULT_STATE)
        save_state(state)
        return state

    with path.open("r", encoding="utf-8") as fh:
        state = json.load(fh)
    return migrate_state(state)


def save_state(state: dict[str, Any]) -> None:
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    tmp.replace(path)


def migrate_state(state: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(DEFAULT_STATE)
    _deep_update(merged, state)
    merged["version"] = STATE_VERSION
    return merged


def _deep_update(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_update(target[key], value)
        else:
            target[key] = value


def slugify(value: str, fallback: str = "node") -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9_.-]+", "-", value)
    value = value.strip("-._")
    return value or fallback


def unique_tag(state: dict[str, Any], preferred: str) -> str:
    base = slugify(preferred)
    tag = base
    index = 2
    reserved = {"direct", "block", "dns-out", state.get("urltest", {}).get("tag", "auto")}
    while tag in state["outbounds"] or tag in reserved:
        tag = f"{base}-{index}"
        index += 1
    return tag


def add_outbound(
    state: dict[str, Any],
    tag: str,
    outbound: dict[str, Any],
    source: str,
    enabled: bool = True,
    display_name: str | None = None,
) -> str:
    final_tag = unique_tag(state, tag)
    config = copy.deepcopy(outbound)
    config["tag"] = final_tag
    state["outbounds"][final_tag] = {
        "name": display_name or final_tag,
        "source": source,
        "enabled": enabled,
        "config": config,
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    if not state.get("selected_outbound"):
        state["selected_outbound"] = final_tag
    return final_tag


def enabled_outbounds(state: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for tag, item in state["outbounds"].items():
        if item.get("enabled", True):
            config = copy.deepcopy(item["config"])
            config["tag"] = tag
            result.append(config)
    return result


def outbound_display_name(tag: str, item: dict[str, Any]) -> str:
    name = item.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    config = item.get("config", {})
    for key in ("remark", "remarks", "Remark", "Remarks", "ps", "name"):
        value = config.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return tag


def selected_outbound_tag(state: dict[str, Any]) -> str:
    selected = state.get("selected_outbound")
    auto_tag = state.get("urltest", {}).get("tag", "auto")
    if selected == auto_tag:
        if enabled_outbounds(state):
            return auto_tag
        raise TerminalTunError("No enabled proxy outbounds. Add a subscription or manual server first.")
    if selected and selected in state["outbounds"] and state["outbounds"][selected].get("enabled", True):
        return selected

    for tag, item in state["outbounds"].items():
        if item.get("enabled", True):
            state["selected_outbound"] = tag
            return tag

    raise TerminalTunError("No enabled proxy outbounds. Add a subscription or manual server first.")


def remove_subscription_outbounds(state: dict[str, Any], subscription_name: str) -> int:
    source = f"subscription:{subscription_name}"
    tags = [tag for tag, item in state["outbounds"].items() if item.get("source") == source]
    for tag in tags:
        del state["outbounds"][tag]
    if state.get("selected_outbound") in tags:
        state["selected_outbound"] = None
    return len(tags)


def require_existing_file(path: str) -> Path:
    file_path = Path(path).expanduser()
    if not file_path.exists():
        raise TerminalTunError(f"File does not exist: {file_path}")
    if not file_path.is_file():
        raise TerminalTunError(f"Not a file: {file_path}")
    return file_path
