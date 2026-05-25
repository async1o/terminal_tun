# terminal-tun

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![uv](https://img.shields.io/badge/uv-ready-111111)
![sing-box](https://img.shields.io/badge/core-sing--box-00AEEF)
![License](https://img.shields.io/badge/license-MIT-green)

**terminal-tun** is a terminal-first subscription, proxy, and TUN routing manager powered by [`sing-box`](https://sing-box.sagernet.org/).

It is built for the exact workflow where you want to clone a repo on Windows or Linux, add a proxy subscription, choose which domains/apps go through VPN, switch nodes from the console, and optionally make it start automatically.

> Think of it as a small terminal control panel for `sing-box`: this project manages state and generates config; `sing-box` does the networking.

## ✨ Features

- 🔗 Add proxy subscriptions by URL.
- 📦 Import common subscription formats:
  - `vmess://`
  - `vless://`
  - `trojan://`
  - `ss://`
  - `socks://`
  - `http://`
  - `hysteria2://`
  - base64 subscription lists
  - `sing-box` JSON with an `outbounds` array
- 🏷️ Show server names from `Remark`, `remark`, `remarks`, `ps`, `name`, or `tag`.
- ⚡ Auto-select a fast node with `urltest`.
- 🎯 Route by domain suffix, full domain, keyword, process name, or process path.
- 🌍 Route all traffic through VPN when needed.
- 🧠 Built-in DNS hijacking for TUN mode.
- 🚫 Blocks QUIC/HTTP3 by default so browsers fall back to TCP HTTPS.
- 🪟 Windows support.
- 🐧 Linux support.
- 🚀 Autostart support:
  - Windows Startup folder
  - Windows Scheduled Task
  - Linux systemd user service
  - Linux system service
- 🧪 Standard-library tests, no heavy Python dependency tree.

## 🧭 Routing Modes

| Mode | What happens |
| --- | --- |
| `rules` | Only selected domains/apps go through VPN. Everything else goes direct. |
| `all` | All traffic goes through VPN, private LAN addresses stay direct. |
| `direct` | Proxy routing is disabled. |

## 🚀 Quick Start

```bash
uv sync
uv run terminal-tun init
uv run terminal-tun core install
uv run terminal-tun subscription add main "https://your-subscription-url"
uv run terminal-tun mode set all
uv run terminal-tun select
uv run terminal-tun run
```

For TUN mode you usually need elevated permissions:

- Windows: run PowerShell or Windows Terminal as Administrator.
- Linux: run with `sudo`, or grant the needed capabilities to `sing-box`.

## 🪟 Windows Setup

Install `uv`:

```powershell
winget install --id astral-sh.uv
```

Clone and prepare the project:

```powershell
git clone https://github.com/YOUR_USERNAME/terminal-tun.git
cd terminal-tun

uv python install 3.12
uv sync
```

Initialize and install `sing-box`:

```powershell
uv run terminal-tun init
uv run terminal-tun core install
uv run terminal-tun status
```

Add a subscription:

```powershell
uv run terminal-tun subscription add main "https://your-subscription-url"
```

Start VPN mode:

```powershell
uv run terminal-tun mode set all
uv run terminal-tun select auto
uv run terminal-tun run
```

Flush DNS after changing nodes or DNS behavior:

```powershell
ipconfig /flushdns
```

## 🐧 Linux Setup

Install `uv` using the method you prefer from the official `uv` docs, then:

```bash
git clone https://github.com/YOUR_USERNAME/terminal-tun.git
cd terminal-tun

uv python install 3.12
uv sync

uv run terminal-tun init
uv run terminal-tun core install
uv run terminal-tun subscription add main "https://your-subscription-url"
sudo uv run terminal-tun run
```

If you do not want to run the whole CLI with `sudo`, configure capabilities for the downloaded `sing-box` binary according to your distro and security model.

## 🔌 Subscriptions

Add and sync a subscription:

```bash
uv run terminal-tun subscription add main "https://your-subscription-url"
```

Sync all subscriptions:

```bash
uv run terminal-tun subscription sync --all
```

List subscriptions:

```bash
uv run terminal-tun subscription list
```

Remove a subscription and all nodes imported from it:

```bash
uv run terminal-tun subscription remove main
```

## 🖥️ Servers

List all servers:

```bash
uv run terminal-tun server list
```

Filter by country, city, protocol, tag, host, or source:

```bash
uv run terminal-tun server list Германия
uv run terminal-tun server list США
uv run terminal-tun server list vless
uv run terminal-tun server list quattro-tech
```

Example output:

```text
main-5: 🇩🇪 ⭐️ Германия | vless 50.7.157.228:443 source=subscription:main
main-21: 🇫🇷 ⚡️ Франция | vless 198.16.113.170:443 source=subscription:main
main-197: 🇺🇸 США, Нью-Йорк | vless 205.142.241.233:443 source=subscription:main
```

Select by exact tag:

```bash
uv run terminal-tun select main-5
```

Select by a unique name fragment:

```bash
uv run terminal-tun select "Франция"
```

If the fragment is ambiguous, the CLI prints matching options so you can choose the exact tag.

Use automatic latency-based selection:

```bash
uv run terminal-tun select auto
```

`auto` is fast, but not always best for services that block VPN IPs. If ChatGPT or Telegram complains about VPN usage, manually select a different region.

## 🧩 Manual Servers

An IP address is not a proxy by itself. Your VPS must run a supported proxy protocol first.

Add a SOCKS server:

```bash
uv run terminal-tun server add socks my-vps --server 1.2.3.4 --port 1080 --username user --password pass
```

Add a Shadowsocks server:

```bash
uv run terminal-tun server add shadowsocks ss-vps --server 1.2.3.4 --port 8388 --method 2022-blake3-aes-128-gcm --password "secret"
```

Add a Trojan server:

```bash
uv run terminal-tun server add trojan trojan-vps --server vpn.example.com --port 443 --password "secret" --sni vpn.example.com
```

Add a raw `sing-box` outbound JSON:

```bash
uv run terminal-tun server add-json custom ./outbound.json
```

## 🎯 Domain Rules

Use `rules` mode when only selected traffic should go through VPN:

```bash
uv run terminal-tun mode set rules
```

Route a domain suffix:

```bash
uv run terminal-tun rule domain add youtube.com
uv run terminal-tun rule domain add openai.com
uv run terminal-tun rule domain add chatgpt.com
```

Route an exact domain:

```bash
uv run terminal-tun rule domain add api.openai.com --kind full
```

Route by keyword:

```bash
uv run terminal-tun rule domain add googlevideo --kind keyword
```

List rules:

```bash
uv run terminal-tun rule domain list
```

Remove a domain rule:

```bash
uv run terminal-tun rule domain remove youtube.com
```

## 🧠 App Rules

Route by process name:

```bash
uv run terminal-tun rule app add chrome.exe
uv run terminal-tun rule app add Telegram.exe
```

Route by process path:

```bash
uv run terminal-tun rule app add "C:\Program Files\Google\Chrome\Application\chrome.exe" --path
uv run terminal-tun rule app add /usr/bin/telegram-desktop --path
```

List app rules:

```bash
uv run terminal-tun rule app list
```

Process-based routing depends on OS support, permissions, and `sing-box` process detection.

## 🌍 Route Everything

```bash
uv run terminal-tun mode set all
uv run terminal-tun select auto
uv run terminal-tun run
```

Private LAN IPs stay direct, so local network traffic is not forced into the tunnel.

## 🚀 Autostart

Windows, current user:

```powershell
uv run terminal-tun autostart install
```

Windows, Scheduled Task with elevated privileges:

```powershell
uv run terminal-tun autostart install --system
```

Linux, user service:

```bash
uv run terminal-tun autostart install
```

Linux, system service:

```bash
sudo uv run terminal-tun autostart install --system
```

Check status:

```bash
uv run terminal-tun autostart status
```

Remove autostart:

```bash
uv run terminal-tun autostart remove
```

## 🛠️ Core Commands

Install `sing-box`:

```bash
uv run terminal-tun core install
```

Show current core path:

```bash
uv run terminal-tun core which
```

Use an existing `sing-box` binary:

```bash
uv run terminal-tun core path /path/to/sing-box
```

Generate config:

```bash
uv run terminal-tun config generate
```

Validate config with `sing-box`:

```bash
uv run terminal-tun config check
```

Print generated config:

```bash
uv run terminal-tun config print
```

## 📁 File Locations

Windows:

| Purpose | Path |
| --- | --- |
| State | `%APPDATA%\terminal-tun\state.json` |
| Generated config | `%APPDATA%\terminal-tun\sing-box.json` |
| Downloaded core | `%LOCALAPPDATA%\terminal-tun\bin\sing-box.exe` |

Linux:

| Purpose | Path |
| --- | --- |
| State | `~/.config/terminal-tun/state.json` |
| Generated config | `~/.config/terminal-tun/sing-box.json` |
| Downloaded core | `~/.local/share/terminal-tun/bin/sing-box` |

Environment overrides:

```bash
TERMINAL_TUN_HOME=/path/to/config
TERMINAL_TUN_DATA=/path/to/data
SING_BOX_PATH=/path/to/sing-box
```

## 🧯 Troubleshooting

### ChatGPT says “If you are using a VPN, try turning it off”

That usually means OpenAI or Cloudflare does not like the selected exit IP.

Try a different region:

```bash
uv run terminal-tun server list Германия
uv run terminal-tun server list Франция
uv run terminal-tun server list США
uv run terminal-tun select main-21
uv run terminal-tun run
```

`auto` optimizes latency, not IP reputation.

### Browser shows `ERR_NAME_NOT_RESOLVED`

Regenerate/check config and flush DNS:

```powershell
uv run terminal-tun config check
ipconfig /flushdns
uv run terminal-tun run
```

The generated config includes DNS hijacking for TUN mode.

### YouTube works, Telegram or ChatGPT does not

This is usually an exit-node issue. Pick another node manually instead of `auto`.

Good candidates are often regular country nodes, not “mobile”, “LTE”, or “auto” nodes:

```bash
uv run terminal-tun select main-5
uv run terminal-tun select main-21
uv run terminal-tun select main-197
```

### Connection logs mention `192.168.x.x:7680`

That is usually Windows Delivery Optimization on the local network. The config rejects local port `7680` to avoid noisy timeouts.

### Sites are slow in browser

The config rejects UDP/443 by default so Chrome/Edge fall back from QUIC/HTTP3 to TCP HTTPS. If a specific node is still slow, switch servers.

## 🧪 Development

Run tests:

```bash
uv run python -m unittest discover -s tests -v
```

Run a smoke check:

```bash
uv run terminal-tun status
uv run terminal-tun config check
```

Project layout:

```text
terminal_tun/
  cli.py             # CLI commands
  state.py           # persistent state
  subscriptions.py   # subscription import/parsing
  singbox.py         # sing-box config generation
  core.py            # sing-box download/run helpers
  autostart.py       # Windows/Linux autostart
tests/
```

## ⚠️ Current Limitations

- Clash YAML is not fully parsed yet. Use URI/base64 subscriptions or `sing-box` JSON.
- TUN mode usually requires elevated permissions.
- App/process rules depend on OS and `sing-box` support.
- VPN exit IP reputation is outside the project’s control.
- A VPS must run a proxy protocol before it can be added as a server.

## 📜 License

MIT. See [LICENSE](LICENSE).
