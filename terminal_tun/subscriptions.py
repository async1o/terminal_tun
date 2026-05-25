from __future__ import annotations

import base64
import json
import re
import urllib.parse
import urllib.request
from typing import Any

from .errors import TerminalTunError
from .state import slugify


SUPPORTED_SCHEMES = {"vmess", "vless", "trojan", "ss", "socks", "socks5", "http", "hysteria2", "hy2"}


def fetch_subscription(url: str, timeout: int = 30) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "terminal-tun/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except Exception as exc:  # pragma: no cover - network dependent
        raise TerminalTunError(f"Failed to fetch subscription: {exc}") from exc
    return raw.decode("utf-8", errors="replace")


def parse_subscription_payload(payload: str, source_name: str) -> list[dict[str, Any]]:
    text = payload.strip()
    candidates = [text]
    decoded = _try_base64_text(text)
    if decoded and decoded != text:
        candidates.insert(0, decoded)

    outbounds: list[dict[str, Any]] = []
    for candidate in candidates:
        json_outbounds = _parse_json_outbounds(candidate)
        if json_outbounds:
            outbounds.extend(json_outbounds)
            break
        for line in _iter_proxy_lines(candidate):
            try:
                outbound = parse_proxy_uri(line)
            except TerminalTunError:
                continue
            if outbound:
                outbounds.append(outbound)
        if outbounds:
            break

    if not outbounds:
        raise TerminalTunError(
            "No supported nodes found. Supported imports: vmess/vless/trojan/ss/socks/http/hysteria2 URI lists, "
            "base64 URI lists, and sing-box JSON with an outbounds array."
        )

    result: list[dict[str, Any]] = []
    for index, outbound in enumerate(outbounds, start=1):
        name = outbound.pop("_name", None) or outbound.get("tag") or f"{source_name}-{index}"
        outbound["_display_name"] = str(name)
        outbound["tag"] = slugify(f"{source_name}-{index}-{name}")
        result.append(outbound)
    return result


def parse_proxy_uri(uri: str) -> dict[str, Any] | None:
    uri = uri.strip()
    if not uri or uri.startswith("#"):
        return None
    scheme = uri.split(":", 1)[0].lower()
    if scheme not in SUPPORTED_SCHEMES:
        return None

    if scheme == "vmess":
        return _parse_vmess(uri)
    if scheme == "ss":
        return _parse_shadowsocks(uri)
    if scheme in {"socks", "socks5", "http"}:
        return _parse_basic_proxy(uri, "socks" if scheme in {"socks", "socks5"} else "http")
    if scheme == "trojan":
        return _parse_trojan(uri)
    if scheme == "vless":
        return _parse_vless(uri)
    if scheme in {"hysteria2", "hy2"}:
        return _parse_hysteria2(uri)
    return None


def _iter_proxy_lines(text: str) -> list[str]:
    lines: list[str] = []
    for raw_line in text.replace("\r", "\n").split("\n"):
        line = raw_line.strip()
        if not line:
            continue
        if "://" in line:
            lines.append(line)
    return lines


def _parse_json_outbounds(text: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    if isinstance(data, dict):
        values = data.get("outbounds", [])
    elif isinstance(data, list):
        values = data
    else:
        return []

    result: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        outbound = dict(value)
        name = _extract_json_name(outbound)
        outbound_type = outbound.get("type")
        if outbound_type in {None, "direct", "block", "dns", "selector", "urltest"}:
            continue
        if name:
            outbound["_name"] = name
        _drop_metadata_fields(outbound)
        result.append(outbound)
    return result


def _extract_json_name(value: dict[str, Any]) -> str | None:
    for key in ("Remark", "remark", "remarks", "Remarks", "ps", "name", "tag"):
        item = value.get(key)
        if isinstance(item, str) and item.strip():
            return item.strip()
    return None


def _drop_metadata_fields(value: dict[str, Any]) -> None:
    for key in ("Remark", "remark", "remarks", "Remarks", "ps", "name"):
        value.pop(key, None)


def _parse_basic_proxy(uri: str, outbound_type: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(uri)
    if not parsed.hostname or not parsed.port:
        raise TerminalTunError(f"Invalid {outbound_type} URI: {uri}")
    outbound: dict[str, Any] = {
        "type": outbound_type,
        "server": parsed.hostname,
        "server_port": parsed.port,
        "_name": _fragment_name(parsed),
    }
    if parsed.username:
        outbound["username"] = urllib.parse.unquote(parsed.username)
    if parsed.password:
        outbound["password"] = urllib.parse.unquote(parsed.password)
    return outbound


def _parse_trojan(uri: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(uri)
    if not parsed.hostname or not parsed.port or not parsed.username:
        raise TerminalTunError(f"Invalid trojan URI: {uri}")
    query = urllib.parse.parse_qs(parsed.query)
    outbound: dict[str, Any] = {
        "type": "trojan",
        "server": parsed.hostname,
        "server_port": parsed.port,
        "password": urllib.parse.unquote(parsed.username),
        "_name": _fragment_name(parsed),
    }
    _apply_tls(outbound, query, parsed.hostname, default_enabled=True)
    _apply_transport(outbound, query)
    return outbound


def _parse_vless(uri: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(uri)
    if not parsed.hostname or not parsed.port or not parsed.username:
        raise TerminalTunError(f"Invalid vless URI: {uri}")
    query = urllib.parse.parse_qs(parsed.query)
    outbound: dict[str, Any] = {
        "type": "vless",
        "server": parsed.hostname,
        "server_port": parsed.port,
        "uuid": urllib.parse.unquote(parsed.username),
        "_name": _fragment_name(parsed),
    }
    flow = _first(query, "flow")
    if flow:
        outbound["flow"] = flow
    packet_encoding = _first(query, "packetEncoding", "packet_encoding")
    if packet_encoding:
        outbound["packet_encoding"] = packet_encoding
    _apply_tls(outbound, query, parsed.hostname)
    _apply_transport(outbound, query)
    return outbound


def _parse_hysteria2(uri: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(uri)
    if not parsed.hostname or not parsed.port:
        raise TerminalTunError(f"Invalid hysteria2 URI: {uri}")
    query = urllib.parse.parse_qs(parsed.query)
    password = urllib.parse.unquote(parsed.username or _first(query, "password") or "")
    if not password:
        raise TerminalTunError(f"Invalid hysteria2 URI without password: {uri}")
    outbound: dict[str, Any] = {
        "type": "hysteria2",
        "server": parsed.hostname,
        "server_port": parsed.port,
        "password": password,
        "_name": _fragment_name(parsed),
    }
    _apply_tls(outbound, query, parsed.hostname, default_enabled=True)
    return outbound


def _parse_vmess(uri: str) -> dict[str, Any]:
    raw = uri[len("vmess://") :]
    if "@" in raw:
        return _parse_vmess_uri(uri)

    decoded = _b64decode_text(raw)
    try:
        data = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise TerminalTunError(f"Invalid vmess JSON: {exc}") from exc

    server = data.get("add")
    port = _int_or_none(data.get("port"))
    uuid = data.get("id")
    if not server or not port or not uuid:
        raise TerminalTunError("Invalid vmess node: missing add/port/id")

    outbound: dict[str, Any] = {
        "type": "vmess",
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "security": data.get("scy") or data.get("security") or "auto",
        "alter_id": _int_or_none(data.get("aid")) or 0,
        "_name": data.get("ps") or server,
    }

    if str(data.get("tls", "")).lower() == "tls":
        outbound["tls"] = {"enabled": True}
        if data.get("sni"):
            outbound["tls"]["server_name"] = data["sni"]

    net = data.get("net")
    if net == "ws":
        transport: dict[str, Any] = {"type": "ws"}
        if data.get("path"):
            transport["path"] = data["path"]
        if data.get("host"):
            transport["headers"] = {"Host": data["host"]}
        outbound["transport"] = transport
    elif net == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": data.get("path") or ""}
    return outbound


def _parse_vmess_uri(uri: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(uri)
    if not parsed.hostname or not parsed.port or not parsed.username:
        raise TerminalTunError(f"Invalid vmess URI: {uri}")
    query = urllib.parse.parse_qs(parsed.query)
    outbound: dict[str, Any] = {
        "type": "vmess",
        "server": parsed.hostname,
        "server_port": parsed.port,
        "uuid": urllib.parse.unquote(parsed.username),
        "security": _first(query, "security") or "auto",
        "alter_id": _int_or_none(_first(query, "alterId", "alter_id")) or 0,
        "_name": _fragment_name(parsed),
    }
    _apply_tls(outbound, query, parsed.hostname)
    _apply_transport(outbound, query)
    return outbound


def _parse_shadowsocks(uri: str) -> dict[str, Any]:
    body = uri[len("ss://") :]
    fragment = ""
    if "#" in body:
        body, fragment = body.split("#", 1)
    if "?" in body:
        body, _ = body.split("?", 1)

    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        if ":" not in userinfo:
            userinfo = _b64decode_text(userinfo)
    else:
        decoded = _b64decode_text(body)
        if "@" not in decoded:
            raise TerminalTunError(f"Invalid shadowsocks URI: {uri}")
        userinfo, hostport = decoded.rsplit("@", 1)

    if ":" not in userinfo:
        raise TerminalTunError(f"Invalid shadowsocks user info: {uri}")
    method, password = userinfo.split(":", 1)
    host, port = _split_host_port(hostport)
    return {
        "type": "shadowsocks",
        "server": host,
        "server_port": port,
        "method": urllib.parse.unquote(method),
        "password": urllib.parse.unquote(password),
        "_name": urllib.parse.unquote(fragment) if fragment else host,
    }


def _apply_tls(
    outbound: dict[str, Any],
    query: dict[str, list[str]],
    server_name: str,
    default_enabled: bool = False,
) -> None:
    security = (_first(query, "security") or "").lower()
    sni = _first(query, "sni", "peer", "serverName", "servername")
    insecure = (_first(query, "allowInsecure", "insecure") or "").lower() in {"1", "true", "yes"}
    alpn = _first(query, "alpn")
    enabled = default_enabled or security in {"tls", "reality"} or bool(sni)
    if not enabled:
        return
    tls: dict[str, Any] = {"enabled": True}
    if sni:
        tls["server_name"] = sni
    elif security == "tls":
        tls["server_name"] = server_name
    if insecure:
        tls["insecure"] = True
    if alpn:
        tls["alpn"] = [item for item in re.split(r"[,|]", alpn) if item]
    if security == "reality":
        fingerprint = _first(query, "fp", "fingerprint") or "chrome"
        public_key = _first(query, "pbk", "publicKey", "public_key")
        short_id = _first(query, "sid", "shortId", "short_id")
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
        tls["reality"] = {"enabled": True}
        if public_key:
            tls["reality"]["public_key"] = public_key
        if short_id:
            tls["reality"]["short_id"] = short_id
    outbound["tls"] = tls


def _apply_transport(outbound: dict[str, Any], query: dict[str, list[str]]) -> None:
    transport_type = (_first(query, "type", "net") or "").lower()
    if transport_type in {"tcp", ""}:
        return
    if transport_type == "ws":
        transport: dict[str, Any] = {"type": "ws"}
        path = _first(query, "path")
        host = _first(query, "host")
        if path:
            transport["path"] = path
        if host:
            transport["headers"] = {"Host": host}
        outbound["transport"] = transport
    elif transport_type == "grpc":
        service_name = _first(query, "serviceName", "service_name", "path") or ""
        outbound["transport"] = {"type": "grpc", "service_name": service_name}
    elif transport_type in {"http", "h2"}:
        outbound["transport"] = {"type": "http"}


def _fragment_name(parsed: urllib.parse.ParseResult) -> str:
    return urllib.parse.unquote(parsed.fragment) if parsed.fragment else parsed.hostname or "node"


def _first(query: dict[str, list[str]], *keys: str) -> str | None:
    for key in keys:
        value = query.get(key)
        if value:
            return urllib.parse.unquote(value[0])
    return None


def _try_base64_text(text: str) -> str | None:
    compact = "".join(text.split())
    if len(compact) < 8:
        return None
    try:
        decoded = _b64decode_text(compact)
    except TerminalTunError:
        return None
    return decoded if "://" in decoded or decoded.lstrip().startswith(("{", "[")) else None


def _b64decode_text(value: str) -> str:
    value = value.strip()
    value = value.replace("-", "+").replace("_", "/")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value + padding, validate=False).decode("utf-8", errors="replace")
    except Exception as exc:
        raise TerminalTunError("Invalid base64 payload") from exc


def _split_host_port(value: str) -> tuple[str, int]:
    parsed = urllib.parse.urlparse(f"//{value}")
    if not parsed.hostname or not parsed.port:
        raise TerminalTunError(f"Invalid host:port: {value}")
    return parsed.hostname, parsed.port


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
