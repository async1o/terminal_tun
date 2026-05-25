from __future__ import annotations

import copy
import json
import platform
from pathlib import Path
from typing import Any

from .paths import generated_config_path
from .state import enabled_outbounds, selected_outbound_tag


def generate_config(state: dict[str, Any], target_platform: str | None = None) -> dict[str, Any]:
    system = (target_platform or platform.system()).lower()
    mode = state.get("mode", "rules")
    proxy_outbounds = [_normalize_outbound(outbound) for outbound in enabled_outbounds(state)]
    selected = selected_outbound_tag(state) if mode != "direct" else "direct"
    outbounds = _outbounds_with_groups(state, proxy_outbounds, selected)

    config: dict[str, Any] = {
        "log": {
            "level": "info",
            "timestamp": True,
        },
        "dns": _dns(state),
        "inbounds": _inbounds(state, system),
        "outbounds": outbounds
        + [
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": "cloudflare",
            "rules": _route_rules(state, selected, mode, system),
            "final": selected if mode == "all" else "direct",
        },
    }

    if _has_process_rules(state) and mode != "direct":
        config["route"]["find_process"] = True

    return config


def _dns(state: dict[str, Any]) -> dict[str, Any]:
    dns = state.get("dns", {})
    return {
        "servers": [
            {
                "type": "udp",
                "tag": "cloudflare",
                "server": dns.get("server", "1.1.1.1"),
            },
            {
                "type": "udp",
                "tag": "google",
                "server": dns.get("fallback_server", "8.8.8.8"),
            },
        ],
        "rules": [
            {
                "query_type": ["A", "AAAA"],
                "server": "cloudflare",
            }
        ],
        "final": "cloudflare",
        "strategy": dns.get("strategy", "prefer_ipv4"),
        "cache_capacity": int(dns.get("cache_capacity", 4096)),
    }


def write_config(state: dict[str, Any], path: Path | None = None, target_platform: str | None = None) -> Path:
    output_path = path or generated_config_path()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    config = generate_config(state, target_platform=target_platform)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return output_path


def _inbounds(state: dict[str, Any], system: str) -> list[dict[str, Any]]:
    inbounds: list[dict[str, Any]] = []
    mixed = state.get("mixed", {})
    if mixed.get("enabled", True):
        inbounds.append(
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": mixed.get("listen", "127.0.0.1"),
                "listen_port": int(mixed.get("listen_port", 2080)),
            }
        )

    tun = state.get("tun", {})
    if tun.get("enabled", True):
        inbound: dict[str, Any] = {
            "type": "tun",
            "tag": "tun-in",
            "interface_name": tun.get("interface_name", "terminaltun0"),
            "address": [tun.get("address", "172.28.0.1/30")],
            "mtu": _tun_mtu(tun, system),
            "auto_route": True,
            "strict_route": bool(tun.get("strict_route", True)),
            "stack": "mixed",
        }
        if system == "linux":
            inbound["auto_redirect"] = True
        inbounds.append(inbound)
    return inbounds


def _route_rules(state: dict[str, Any], selected: str, mode: str, system: str) -> list[dict[str, Any]]:
    if mode == "direct":
        return []

    inbounds = _enabled_inbound_tags(state)
    result: list[dict[str, Any]] = []
    if inbounds and _needs_sniff(state, mode):
        result.append({"inbound": inbounds, "action": "sniff"})

    routing = state.get("routing", {})
    result.append({"port": 53, "action": "hijack-dns"})
    if system == "windows" and routing.get("reject_windows_delivery_optimization", True):
        result.append({"ip_is_private": True, "port": 7680, "action": "reject"})
    if routing.get("block_quic", True):
        result.append({"network": "udp", "port": 443, "action": "reject"})

    if mode == "all":
        result.append(_route_rule("direct", ip_is_private=True))
        return result

    rules = state.get("rules", {})
    result.append(_route_rule("direct", ip_is_private=True))
    _append_rule(result, "domain", rules.get("domains"), selected)
    _append_rule(result, "domain_suffix", rules.get("domain_suffixes"), selected)
    _append_rule(result, "domain_keyword", rules.get("domain_keywords"), selected)
    _append_rule(result, "process_name", rules.get("process_names"), selected)
    _append_rule(result, "process_path", rules.get("process_paths"), selected)
    return result


def _append_rule(result: list[dict[str, Any]], key: str, values: list[str] | None, outbound: str) -> None:
    clean = sorted({value.strip() for value in values or [] if value.strip()})
    if clean:
        result.append(_route_rule(outbound, **{key: clean}))


def _route_rule(outbound: str, **matchers: Any) -> dict[str, Any]:
    return {**matchers, "action": "route", "outbound": outbound}


def _enabled_inbound_tags(state: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    if state.get("mixed", {}).get("enabled", True):
        tags.append("mixed-in")
    if state.get("tun", {}).get("enabled", True):
        tags.append("tun-in")
    return tags


def _normalize_outbound(outbound: dict[str, Any]) -> dict[str, Any]:
    outbound = copy.deepcopy(outbound)
    tls = outbound.get("tls")
    if isinstance(tls, dict) and isinstance(tls.get("reality"), dict) and tls["reality"].get("enabled", True):
        tls.setdefault("utls", {"enabled": True, "fingerprint": "chrome"})
    return outbound


def _has_process_rules(state: dict[str, Any]) -> bool:
    rules = state.get("rules", {})
    return bool(rules.get("process_names") or rules.get("process_paths"))


def _needs_sniff(state: dict[str, Any], mode: str) -> bool:
    if mode != "rules":
        return False
    rules = state.get("rules", {})
    return bool(rules.get("domains") or rules.get("domain_suffixes") or rules.get("domain_keywords"))


def _outbounds_with_groups(state: dict[str, Any], outbounds: list[dict[str, Any]], selected: str) -> list[dict[str, Any]]:
    result = list(outbounds)
    urltest = state.get("urltest", {})
    auto_tag = urltest.get("tag", "auto")
    if selected != auto_tag or not urltest.get("enabled", True):
        return result

    tags = [outbound["tag"] for outbound in outbounds]
    result.append(
        {
            "type": "urltest",
            "tag": auto_tag,
            "outbounds": tags,
            "url": urltest.get("url", "https://www.gstatic.com/generate_204"),
            "interval": urltest.get("interval", "3m"),
            "tolerance": int(urltest.get("tolerance", 50)),
        }
    )
    return result


def _tun_mtu(tun: dict[str, Any], system: str) -> int:
    mtu = int(tun.get("mtu", 9000))
    if system == "windows" and mtu > 1500:
        return 1500
    return mtu


def printable_config(state: dict[str, Any], target_platform: str | None = None) -> str:
    return json.dumps(generate_config(copy.deepcopy(state), target_platform=target_platform), indent=2, ensure_ascii=False)
