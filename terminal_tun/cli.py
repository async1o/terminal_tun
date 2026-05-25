from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .autostart import autostart_status, install_autostart, remove_autostart
from .core import check_config, find_core, install_core, run_core
from .errors import TerminalTunError
from .paths import generated_config_path, state_path
from .singbox import printable_config, write_config
from .state import (
    add_outbound,
    load_state,
    outbound_display_name,
    remove_subscription_outbounds,
    require_existing_file,
    save_state,
    selected_outbound_tag,
    utc_now,
)
from .subscriptions import fetch_subscription, parse_subscription_payload


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return dispatch(args)
    except TerminalTunError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8", errors="replace")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="terminal-tun", description="Terminal manager for sing-box TUN routing.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create the local state file.")
    sub.add_parser("status", help="Show current configuration summary.")

    tun = sub.add_parser("tun", help="Inspect or change TUN settings.")
    tun_sub = tun.add_subparsers(dest="tun_command", required=True)
    tun_sub.add_parser("show", help="Show current TUN settings.")
    tun_mtu = tun_sub.add_parser("mtu", help="Show or set TUN MTU.")
    tun_mtu.add_argument("value", nargs="?", type=int)

    mode = sub.add_parser("mode", help="Show or change routing mode.")
    mode_sub = mode.add_subparsers(dest="mode_command", required=True)
    mode_sub.add_parser("show", help="Show current mode.")
    mode_set = mode_sub.add_parser("set", help="Set routing mode.")
    mode_set.add_argument("mode", choices=["rules", "all", "direct"])

    select = sub.add_parser("select", help="Select default proxy outbound by tag or unique name fragment.")
    select.add_argument("target", nargs="?")

    profile = sub.add_parser("profile", aliases=["template"], help="Manage routing config profiles.")
    profile_sub = profile.add_subparsers(dest="profile_command", required=True)
    profile_sub.add_parser("list", help="List saved routing profiles.")
    profile_show = profile_sub.add_parser("show", help="Show one routing profile.")
    profile_show.add_argument("name")
    profile_save = profile_sub.add_parser("save", help="Save current mode and routing rules as a profile.")
    profile_save.add_argument("name")
    profile_save.add_argument("--description", default="")
    profile_create = profile_sub.add_parser("create", help="Create a profile from command-line domain/app rules.")
    profile_create.add_argument("name")
    profile_create.add_argument("--description", default="")
    profile_create.add_argument("--domain", action="append", default=[])
    profile_create.add_argument("--full-domain", action="append", default=[])
    profile_create.add_argument("--keyword", action="append", default=[])
    profile_create.add_argument("--app", action="append", default=[])
    profile_create.add_argument("--process-path", action="append", default=[])
    profile_apply = profile_sub.add_parser("apply", aliases=["use"], help="Apply a saved profile to active routing rules.")
    profile_apply.add_argument("name")
    profile_delete = profile_sub.add_parser("delete", aliases=["remove"], help="Delete a saved profile.")
    profile_delete.add_argument("name")
    profile_add_domain = profile_sub.add_parser("add-domain", help="Add a domain rule to a saved profile.")
    profile_add_domain.add_argument("name")
    profile_add_domain.add_argument("value")
    profile_add_domain.add_argument("--kind", choices=["auto", "full", "suffix", "keyword"], default="auto")
    profile_remove_domain = profile_sub.add_parser("remove-domain", help="Remove a domain rule from a saved profile.")
    profile_remove_domain.add_argument("name")
    profile_remove_domain.add_argument("value")
    profile_add_app = profile_sub.add_parser("add-app", help="Add an app/process rule to a saved profile.")
    profile_add_app.add_argument("name")
    profile_add_app.add_argument("value")
    profile_add_app.add_argument("--path", action="store_true")
    profile_remove_app = profile_sub.add_parser("remove-app", help="Remove an app/process rule from a saved profile.")
    profile_remove_app.add_argument("name")
    profile_remove_app.add_argument("value")

    subscription = sub.add_parser("subscription", aliases=["sub"], help="Manage subscriptions.")
    subscription_sub = subscription.add_subparsers(dest="subscription_command", required=True)
    sub_add = subscription_sub.add_parser("add", help="Add and sync a subscription URL.")
    sub_add.add_argument("name")
    sub_add.add_argument("url")
    sub_add.add_argument("--no-sync", action="store_true")
    sub_sync = subscription_sub.add_parser("sync", help="Sync subscriptions.")
    sub_sync.add_argument("name", nargs="?")
    sub_sync.add_argument("--all", action="store_true")
    subscription_sub.add_parser("list", help="List subscriptions.")
    sub_remove = subscription_sub.add_parser("remove", help="Remove a subscription and its nodes.")
    sub_remove.add_argument("name")

    server = sub.add_parser("server", help="Manage manual proxy servers.")
    server_sub = server.add_subparsers(dest="server_command", required=True)
    server_add = server_sub.add_parser("add", help="Add a manual server.")
    server_add.add_argument("protocol", choices=["socks", "http", "shadowsocks", "trojan", "vless", "vmess", "hysteria2"])
    server_add.add_argument("name")
    server_add.add_argument("--server", required=True)
    server_add.add_argument("--port", required=True, type=int)
    server_add.add_argument("--username")
    server_add.add_argument("--password")
    server_add.add_argument("--uuid")
    server_add.add_argument("--method")
    server_add.add_argument("--security", default="auto")
    server_add.add_argument("--alter-id", type=int, default=0)
    server_add.add_argument("--tls", action="store_true")
    server_add.add_argument("--sni")
    server_add.add_argument("--insecure", action="store_true")
    server_json = server_sub.add_parser("add-json", help="Add a raw sing-box outbound JSON file.")
    server_json.add_argument("name")
    server_json.add_argument("file")
    server_list = server_sub.add_parser("list", help="List manual and imported servers.")
    server_list.add_argument("query", nargs="?", help="Optional case-insensitive filter by tag, remark, type, host, or source.")
    server_remove = server_sub.add_parser("remove", help="Remove a server by tag.")
    server_remove.add_argument("tag")

    rule = sub.add_parser("rule", help="Manage routing rules.")
    rule_sub = rule.add_subparsers(dest="rule_command", required=True)
    domain = rule_sub.add_parser("domain", help="Manage domain routing rules.")
    domain_sub = domain.add_subparsers(dest="domain_command", required=True)
    domain_add = domain_sub.add_parser("add")
    domain_add.add_argument("value")
    domain_add.add_argument("--kind", choices=["auto", "full", "suffix", "keyword"], default="auto")
    domain_remove = domain_sub.add_parser("remove")
    domain_remove.add_argument("value")
    domain_sub.add_parser("list")
    app = rule_sub.add_parser("app", help="Manage application/process routing rules.")
    app_sub = app.add_subparsers(dest="app_command", required=True)
    app_add = app_sub.add_parser("add")
    app_add.add_argument("value")
    app_add.add_argument("--path", action="store_true")
    app_remove = app_sub.add_parser("remove")
    app_remove.add_argument("value")
    app_sub.add_parser("list")

    config = sub.add_parser("config", help="Generate or check sing-box config.")
    config_sub = config.add_subparsers(dest="config_command", required=True)
    config_sub.add_parser("generate")
    config_sub.add_parser("print")
    config_sub.add_parser("check")

    core = sub.add_parser("core", help="Install or configure sing-box.")
    core_sub = core.add_subparsers(dest="core_command", required=True)
    core_install = core_sub.add_parser("install")
    core_install.add_argument("--version", default="latest")
    core_path = core_sub.add_parser("path")
    core_path.add_argument("path", nargs="?")
    core_sub.add_parser("which")

    run = sub.add_parser("run", help="Generate config and run sing-box. Extra args after -- are passed to sing-box.")
    run.add_argument("--config", type=Path)
    run.add_argument("extra", nargs=argparse.REMAINDER)

    autostart = sub.add_parser("autostart", aliases=["service"], help="Install/remove autostart.")
    autostart_sub = autostart.add_subparsers(dest="autostart_command", required=True)
    auto_install = autostart_sub.add_parser("install")
    auto_install.add_argument("--system", action="store_true")
    auto_remove = autostart_sub.add_parser("remove")
    auto_remove.add_argument("--system", action="store_true")
    auto_status = autostart_sub.add_parser("status")
    auto_status.add_argument("--system", action="store_true")

    return parser


def dispatch(args: argparse.Namespace) -> int:
    if args.command == "init":
        state = load_state()
        save_state(state)
        print(f"state: {state_path()}")
        return 0
    if args.command == "status":
        return cmd_status()
    if args.command == "tun":
        return cmd_tun(args)
    if args.command == "mode":
        return cmd_mode(args)
    if args.command == "select":
        return cmd_select(args)
    if args.command in {"profile", "template"}:
        return cmd_profile(args)
    if args.command in {"subscription", "sub"}:
        return cmd_subscription(args)
    if args.command == "server":
        return cmd_server(args)
    if args.command == "rule":
        return cmd_rule(args)
    if args.command == "config":
        return cmd_config(args)
    if args.command == "core":
        return cmd_core(args)
    if args.command == "run":
        return cmd_run(args)
    if args.command in {"autostart", "service"}:
        return cmd_autostart(args)
    raise TerminalTunError(f"Unknown command: {args.command}")


def cmd_status() -> int:
    state = load_state()
    selected = state.get("selected_outbound")
    try:
        selected = selected_outbound_tag(state)
    except TerminalTunError:
        selected = None
    print(f"state: {state_path()}")
    print(f"generated config: {generated_config_path()}")
    print(f"mode: {state.get('mode')}")
    print(f"active profile: {state.get('active_profile') or '-'}")
    print(f"selected outbound: {selected or '-'}")
    print(f"subscriptions: {len(state['subscriptions'])}")
    print(f"outbounds: {len(state['outbounds'])}")
    rules = state.get("rules", {})
    print(f"domain rules: {len(rules.get('domains', [])) + len(rules.get('domain_suffixes', [])) + len(rules.get('domain_keywords', []))}")
    print(f"app rules: {len(rules.get('process_names', [])) + len(rules.get('process_paths', []))}")
    try:
        print(f"sing-box: {find_core(state)}")
    except TerminalTunError as exc:
        print(f"sing-box: not found ({exc})")
    return 0


def cmd_mode(args: argparse.Namespace) -> int:
    state = load_state()
    if args.mode_command == "show":
        print(state.get("mode", "rules"))
        return 0
    state["mode"] = args.mode
    state["active_profile"] = None
    save_state(state)
    print(f"mode set: {args.mode}")
    return 0


def cmd_tun(args: argparse.Namespace) -> int:
    state = load_state()
    tun = state.setdefault("tun", {})
    if args.tun_command == "show":
        print(f"enabled: {tun.get('enabled', True)}")
        print(f"interface_name: {tun.get('interface_name', 'terminaltun0')}")
        print(f"address: {tun.get('address', '172.28.0.1/30')}")
        print(f"mtu: {tun.get('mtu', 9000)}")
        print(f"strict_route: {tun.get('strict_route', True)}")
        return 0
    if args.tun_command == "mtu":
        if args.value is None:
            print(tun.get("mtu", 9000))
            return 0
        if args.value < 576 or args.value > 9000:
            raise TerminalTunError("MTU must be between 576 and 9000.")
        tun["mtu"] = args.value
        save_state(state)
        print(f"tun mtu set: {args.value}")
        return 0
    raise TerminalTunError(f"Unknown tun command: {args.tun_command}")


def cmd_select(args: argparse.Namespace) -> int:
    state = load_state()
    auto_tag = state.get("urltest", {}).get("tag", "auto")
    if not args.target:
        auto_marker = "*" if state.get("selected_outbound") == auto_tag else " "
        print(f"{auto_marker} {auto_tag}: urltest fastest node")
        for tag, item in state["outbounds"].items():
            marker = "*" if tag == state.get("selected_outbound") else " "
            print(f"{marker} {tag}: {outbound_display_name(tag, item)} [{item.get('source')}]")
        return 0
    tag = _resolve_outbound_target(state, args.target, auto_tag)
    state["selected_outbound"] = tag
    save_state(state)
    print(f"selected outbound: {tag}")
    return 0


def cmd_profile(args: argparse.Namespace) -> int:
    state = load_state()
    profiles = state.setdefault("profiles", {})
    command = args.profile_command

    if command == "list":
        if not profiles:
            print("no profiles")
            return 0
        active = state.get("active_profile")
        for name, profile in sorted(profiles.items()):
            marker = "*" if name == active else " "
            rules = profile.get("rules", {})
            domain_count = _domain_rule_count(rules)
            app_count = _app_rule_count(rules)
            description = profile.get("description") or "-"
            print(f"{marker} {name}: mode={profile.get('mode', 'rules')} domains={domain_count} apps={app_count} description={description}")
        return 0

    if command == "show":
        _print_profile(args.name, _get_profile(state, args.name))
        return 0

    if command == "save":
        now = utc_now()
        existing = profiles.get(args.name, {})
        profiles[args.name] = {
            "mode": state.get("mode", "rules"),
            "rules": _copy_rules(state.get("rules", {})),
            "description": args.description or existing.get("description", ""),
            "created_at": existing.get("created_at", now),
            "updated_at": now,
        }
        state["active_profile"] = args.name
        save_state(state)
        print(f"profile saved: {args.name}")
        return 0

    if command == "create":
        if args.name in profiles:
            raise TerminalTunError(f"Profile already exists: {args.name}")
        rules = _empty_rules()
        for value in args.domain:
            _profile_add_domain(rules, value, "auto")
        for value in args.full_domain:
            _profile_add_domain(rules, value, "full")
        for value in args.keyword:
            _profile_add_domain(rules, value, "keyword")
        for value in args.app:
            _profile_add_app(rules, value, path=False)
        for value in args.process_path:
            _profile_add_app(rules, value, path=True)
        now = utc_now()
        profiles[args.name] = {
            "mode": "rules",
            "rules": rules,
            "description": args.description,
            "created_at": now,
            "updated_at": now,
        }
        save_state(state)
        print(f"profile created: {args.name}")
        return 0

    if command in {"apply", "use"}:
        profile = _get_profile(state, args.name)
        state["rules"] = _copy_rules(profile.get("rules", {}))
        state["mode"] = profile.get("mode", "rules")
        state["active_profile"] = args.name
        save_state(state)
        print(f"profile applied: {args.name}")
        return 0

    if command in {"delete", "remove"}:
        if args.name not in profiles:
            raise TerminalTunError(f"Unknown profile: {args.name}")
        del profiles[args.name]
        if state.get("active_profile") == args.name:
            state["active_profile"] = None
        save_state(state)
        print(f"profile deleted: {args.name}")
        return 0

    if command == "add-domain":
        profile = _get_profile(state, args.name)
        rules = profile.setdefault("rules", _empty_rules())
        key, value = _profile_add_domain(rules, args.value, args.kind)
        profile["updated_at"] = utc_now()
        _sync_active_profile_rules(state, args.name)
        save_state(state)
        print(f"profile domain added: {args.name} {value} ({key})")
        return 0

    if command == "remove-domain":
        profile = _get_profile(state, args.name)
        rules = profile.setdefault("rules", _empty_rules())
        removed = _profile_remove_domain(rules, args.value)
        profile["updated_at"] = utc_now()
        _sync_active_profile_rules(state, args.name)
        save_state(state)
        print(f"profile domain rules removed: {removed}")
        return 0

    if command == "add-app":
        profile = _get_profile(state, args.name)
        rules = profile.setdefault("rules", _empty_rules())
        key, value = _profile_add_app(rules, args.value, args.path)
        profile["updated_at"] = utc_now()
        _sync_active_profile_rules(state, args.name)
        save_state(state)
        print(f"profile app added: {args.name} {value} ({key})")
        return 0

    if command == "remove-app":
        profile = _get_profile(state, args.name)
        rules = profile.setdefault("rules", _empty_rules())
        removed = _profile_remove_app(rules, args.value)
        profile["updated_at"] = utc_now()
        _sync_active_profile_rules(state, args.name)
        save_state(state)
        print(f"profile app rules removed: {removed}")
        return 0

    raise TerminalTunError(f"Unknown profile command: {command}")


def cmd_subscription(args: argparse.Namespace) -> int:
    state = load_state()
    command = args.subscription_command
    if command == "add":
        if args.name in state["subscriptions"]:
            raise TerminalTunError(f"Subscription already exists: {args.name}")
        state["subscriptions"][args.name] = {
            "url": args.url,
            "enabled": True,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "last_sync": None,
        }
        save_state(state)
        print(f"subscription added: {args.name}")
        if not args.no_sync:
            return _sync_subscription(args.name)
        return 0
    if command == "sync":
        if args.all:
            names = list(state["subscriptions"])
        elif args.name:
            names = [args.name]
        else:
            names = list(state["subscriptions"])
        if not names:
            print("no subscriptions")
            return 0
        total = 0
        for name in names:
            total += _sync_subscription(name, quiet=False)
        print(f"synced subscriptions: {len(names)}, nodes: {total}")
        return 0
    if command == "list":
        for name, item in state["subscriptions"].items():
            print(f"{name}: {item['url']} last_sync={item.get('last_sync') or '-'}")
        return 0
    if command == "remove":
        if args.name not in state["subscriptions"]:
            raise TerminalTunError(f"Unknown subscription: {args.name}")
        removed = remove_subscription_outbounds(state, args.name)
        del state["subscriptions"][args.name]
        save_state(state)
        print(f"subscription removed: {args.name} ({removed} nodes)")
        return 0
    raise TerminalTunError(f"Unknown subscription command: {command}")


def _sync_subscription(name: str, quiet: bool = False) -> int:
    state = load_state()
    item = state["subscriptions"].get(name)
    if not item:
        raise TerminalTunError(f"Unknown subscription: {name}")
    payload = fetch_subscription(item["url"])
    outbounds = parse_subscription_payload(payload, source_name=name)
    remove_subscription_outbounds(state, name)
    added = 0
    for outbound in outbounds:
        tag = outbound.pop("tag")
        display_name = outbound.pop("_display_name", None)
        add_outbound(state, tag, outbound, source=f"subscription:{name}", display_name=display_name)
        added += 1
    state["subscriptions"][name]["last_sync"] = utc_now()
    state["subscriptions"][name]["updated_at"] = utc_now()
    save_state(state)
    if not quiet:
        print(f"subscription synced: {name} ({added} nodes)")
    return added


def cmd_server(args: argparse.Namespace) -> int:
    state = load_state()
    command = args.server_command
    if command == "add":
        outbound = _manual_outbound(args)
        tag = add_outbound(state, args.name, outbound, source="manual", display_name=args.name)
        save_state(state)
        print(f"server added: {tag}")
        return 0
    if command == "add-json":
        file_path = require_existing_file(args.file)
        with file_path.open("r", encoding="utf-8") as fh:
            outbound = json.load(fh)
        if not isinstance(outbound, dict) or "type" not in outbound:
            raise TerminalTunError("JSON file must contain a sing-box outbound object.")
        display_name = _json_display_name(outbound) or args.name
        _drop_json_metadata(outbound)
        outbound.pop("tag", None)
        tag = add_outbound(state, args.name, outbound, source="manual", display_name=display_name)
        save_state(state)
        print(f"server added: {tag}")
        return 0
    if command == "list":
        for tag, item in state["outbounds"].items():
            if args.query and not _matches_outbound_query(args.query, tag, item):
                continue
            config = item["config"]
            server = config.get("server", "-")
            port = config.get("server_port", "-")
            selected = "*" if state.get("selected_outbound") == tag else " "
            print(f"{selected} {tag}: {outbound_display_name(tag, item)} | {config.get('type')} {server}:{port} source={item.get('source')}")
        return 0
    if command == "remove":
        if args.tag not in state["outbounds"]:
            raise TerminalTunError(f"Unknown outbound tag: {args.tag}")
        del state["outbounds"][args.tag]
        if state.get("selected_outbound") == args.tag:
            state["selected_outbound"] = None
        save_state(state)
        print(f"server removed: {args.tag}")
        return 0
    raise TerminalTunError(f"Unknown server command: {command}")


def _resolve_outbound_target(state: dict[str, Any], target: str, auto_tag: str) -> str:
    if target == auto_tag:
        return auto_tag
    if target in state["outbounds"]:
        return target

    needle = target.casefold()
    matches: list[tuple[str, str]] = []
    for tag, item in state["outbounds"].items():
        name = outbound_display_name(tag, item)
        if needle in tag.casefold() or needle in name.casefold():
            matches.append((tag, name))

    if not matches:
        raise TerminalTunError(f"Unknown outbound: {target}")
    if len(matches) == 1:
        return matches[0][0]

    preview = "\n".join(f"  {tag}: {name}" for tag, name in matches[:20])
    extra = "" if len(matches) <= 20 else f"\n  ... and {len(matches) - 20} more"
    raise TerminalTunError(f"Ambiguous outbound name fragment: {target}\n{preview}{extra}")


def _matches_outbound_query(query: str, tag: str, item: dict[str, Any]) -> bool:
    config = item.get("config", {})
    haystack = " ".join(
        str(value)
        for value in (
            tag,
            outbound_display_name(tag, item),
            item.get("source", ""),
            config.get("type", ""),
            config.get("server", ""),
            config.get("server_port", ""),
        )
    ).casefold()
    return query.casefold() in haystack


def _manual_outbound(args: argparse.Namespace) -> dict[str, Any]:
    outbound: dict[str, Any] = {
        "type": args.protocol,
        "server": args.server,
        "server_port": args.port,
    }
    if args.protocol in {"socks", "http"}:
        if args.username:
            outbound["username"] = args.username
        if args.password:
            outbound["password"] = args.password
    elif args.protocol == "shadowsocks":
        if not args.method or not args.password:
            raise TerminalTunError("shadowsocks requires --method and --password")
        outbound["method"] = args.method
        outbound["password"] = args.password
    elif args.protocol == "trojan":
        if not args.password:
            raise TerminalTunError("trojan requires --password")
        outbound["password"] = args.password
        args.tls = True
    elif args.protocol in {"vless", "vmess"}:
        if not args.uuid:
            raise TerminalTunError(f"{args.protocol} requires --uuid")
        outbound["uuid"] = args.uuid
        if args.protocol == "vmess":
            outbound["security"] = args.security
            outbound["alter_id"] = args.alter_id
    elif args.protocol == "hysteria2":
        if not args.password:
            raise TerminalTunError("hysteria2 requires --password")
        outbound["password"] = args.password
        args.tls = True

    if args.tls or args.sni or args.insecure:
        outbound["tls"] = {"enabled": True}
        if args.sni:
            outbound["tls"]["server_name"] = args.sni
        if args.insecure:
            outbound["tls"]["insecure"] = True
    return outbound


def _json_display_name(value: dict[str, Any]) -> str | None:
    for key in ("Remark", "remark", "remarks", "Remarks", "ps", "name", "tag"):
        item = value.get(key)
        if isinstance(item, str) and item.strip():
            return item.strip()
    return None


def _drop_json_metadata(value: dict[str, Any]) -> None:
    for key in ("Remark", "remark", "remarks", "Remarks", "ps", "name"):
        value.pop(key, None)


def cmd_rule(args: argparse.Namespace) -> int:
    state = load_state()
    if args.rule_command == "domain":
        return _cmd_domain_rule(state, args)
    if args.rule_command == "app":
        return _cmd_app_rule(state, args)
    raise TerminalTunError(f"Unknown rule command: {args.rule_command}")


def _cmd_domain_rule(state: dict[str, Any], args: argparse.Namespace) -> int:
    rules = state["rules"]
    if args.domain_command == "add":
        key, value = _domain_bucket(args.value, args.kind)
        _add_unique(rules[key], value)
        state["active_profile"] = None
        save_state(state)
        print(f"domain rule added: {value} ({key})")
        return 0
    if args.domain_command == "remove":
        removed = 0
        for key in ["domains", "domain_suffixes", "domain_keywords"]:
            removed += _remove_value(rules[key], args.value)
        state["active_profile"] = None
        save_state(state)
        print(f"domain rules removed: {removed}")
        return 0
    if args.domain_command == "list":
        _print_values("domains", rules["domains"])
        _print_values("domain_suffixes", rules["domain_suffixes"])
        _print_values("domain_keywords", rules["domain_keywords"])
        return 0
    raise TerminalTunError(f"Unknown domain command: {args.domain_command}")


def _cmd_app_rule(state: dict[str, Any], args: argparse.Namespace) -> int:
    rules = state["rules"]
    if args.app_command == "add":
        value = args.value.strip()
        key = "process_paths" if args.path or "/" in value or "\\" in value else "process_names"
        _add_unique(rules[key], value)
        state["active_profile"] = None
        save_state(state)
        print(f"app rule added: {value} ({key})")
        return 0
    if args.app_command == "remove":
        removed = _remove_value(rules["process_names"], args.value)
        removed += _remove_value(rules["process_paths"], args.value)
        state["active_profile"] = None
        save_state(state)
        print(f"app rules removed: {removed}")
        return 0
    if args.app_command == "list":
        _print_values("process_names", rules["process_names"])
        _print_values("process_paths", rules["process_paths"])
        return 0
    raise TerminalTunError(f"Unknown app command: {args.app_command}")


def _domain_bucket(value: str, kind: str) -> tuple[str, str]:
    value = value.strip().lower()
    if not value:
        raise TerminalTunError("Domain value is empty.")
    if kind == "full":
        return "domains", value
    if kind == "suffix":
        return "domain_suffixes", value.removeprefix("*.").removeprefix(".")
    if kind == "keyword":
        return "domain_keywords", value
    if value.startswith("*.") or value.startswith("."):
        return "domain_suffixes", value.removeprefix("*.").removeprefix(".")
    if "*" in value:
        return "domain_keywords", value.replace("*", "")
    return "domain_suffixes", value


def cmd_config(args: argparse.Namespace) -> int:
    state = load_state()
    if args.config_command == "generate":
        path = write_config(state)
        print(f"generated: {path}")
        return 0
    if args.config_command == "print":
        print(printable_config(state))
        return 0
    if args.config_command == "check":
        path = write_config(state)
        return check_config(find_core(state), path)
    raise TerminalTunError(f"Unknown config command: {args.config_command}")


def cmd_core(args: argparse.Namespace) -> int:
    state = load_state()
    if args.core_command == "install":
        path = install_core(args.version)
        state["core"]["path"] = str(path)
        save_state(state)
        print(f"sing-box installed: {path}")
        return 0
    if args.core_command == "path":
        if args.path:
            path = Path(args.path).expanduser()
            if not path.exists():
                raise TerminalTunError(f"Path does not exist: {path}")
            state["core"]["path"] = str(path)
            save_state(state)
            print(f"sing-box path set: {path}")
        else:
            print(state.get("core", {}).get("path") or "-")
        return 0
    if args.core_command == "which":
        print(find_core(state))
        return 0
    raise TerminalTunError(f"Unknown core command: {args.core_command}")


def cmd_run(args: argparse.Namespace) -> int:
    state = load_state()
    if args.config:
        config_path = write_config(state, path=args.config)
    else:
        config_path = write_config(state)
    core_path = find_core(state)
    return run_core(core_path, config_path, _clean_extra(args.extra))


def cmd_autostart(args: argparse.Namespace) -> int:
    if args.autostart_command == "install":
        path = install_autostart(system=args.system)
        print(f"autostart installed: {path}")
        return 0
    if args.autostart_command == "remove":
        path = remove_autostart(system=args.system)
        print(f"autostart removed: {path}")
        return 0
    if args.autostart_command == "status":
        print(autostart_status(system=args.system))
        return 0
    raise TerminalTunError(f"Unknown autostart command: {args.autostart_command}")


def _add_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _empty_rules() -> dict[str, list[str]]:
    return {
        "domains": [],
        "domain_suffixes": [],
        "domain_keywords": [],
        "process_names": [],
        "process_paths": [],
    }


def _copy_rules(rules: dict[str, Any]) -> dict[str, list[str]]:
    copied = _empty_rules()
    for key in copied:
        values = rules.get(key, [])
        if isinstance(values, list):
            copied[key] = [str(value) for value in values]
    return copied


def _get_profile(state: dict[str, Any], name: str) -> dict[str, Any]:
    profile = state.setdefault("profiles", {}).get(name)
    if not isinstance(profile, dict):
        raise TerminalTunError(f"Unknown profile: {name}")
    profile["rules"] = _copy_rules(profile.get("rules", {}))
    profile["mode"] = profile.get("mode", "rules")
    return profile


def _print_profile(name: str, profile: dict[str, Any]) -> None:
    print(f"profile: {name}")
    print(f"mode: {profile.get('mode', 'rules')}")
    print(f"description: {profile.get('description') or '-'}")
    print(f"created_at: {profile.get('created_at') or '-'}")
    print(f"updated_at: {profile.get('updated_at') or '-'}")
    rules = _copy_rules(profile.get("rules", {}))
    _print_values("domains", rules["domains"])
    _print_values("domain_suffixes", rules["domain_suffixes"])
    _print_values("domain_keywords", rules["domain_keywords"])
    _print_values("process_names", rules["process_names"])
    _print_values("process_paths", rules["process_paths"])


def _profile_add_domain(rules: dict[str, list[str]], value: str, kind: str) -> tuple[str, str]:
    key, normalized = _domain_bucket(value, kind)
    _add_unique(rules[key], normalized)
    return key, normalized


def _profile_remove_domain(rules: dict[str, list[str]], value: str) -> int:
    removed = 0
    normalized = value.strip().lower()
    for key in ["domains", "domain_suffixes", "domain_keywords"]:
        removed += _remove_value(rules[key], normalized)
    return removed


def _profile_add_app(rules: dict[str, list[str]], value: str, path: bool) -> tuple[str, str]:
    normalized = value.strip()
    if not normalized:
        raise TerminalTunError("App value is empty.")
    key = "process_paths" if path or "/" in normalized or "\\" in normalized else "process_names"
    _add_unique(rules[key], normalized)
    return key, normalized


def _profile_remove_app(rules: dict[str, list[str]], value: str) -> int:
    removed = _remove_value(rules["process_names"], value)
    removed += _remove_value(rules["process_paths"], value)
    return removed


def _sync_active_profile_rules(state: dict[str, Any], name: str) -> None:
    if state.get("active_profile") != name:
        return
    profile = _get_profile(state, name)
    state["rules"] = _copy_rules(profile.get("rules", {}))
    state["mode"] = profile.get("mode", "rules")


def _domain_rule_count(rules: dict[str, Any]) -> int:
    return sum(len(rules.get(key, [])) for key in ["domains", "domain_suffixes", "domain_keywords"])


def _app_rule_count(rules: dict[str, Any]) -> int:
    return sum(len(rules.get(key, [])) for key in ["process_names", "process_paths"])


def _remove_value(values: list[str], value: str) -> int:
    before = len(values)
    values[:] = [item for item in values if item != value]
    return before - len(values)


def _print_values(title: str, values: list[str]) -> None:
    print(f"{title}:")
    for value in values:
        print(f"  {value}")


def _clean_extra(extra: list[str]) -> list[str]:
    if extra and extra[0] == "--":
        return extra[1:]
    return extra
