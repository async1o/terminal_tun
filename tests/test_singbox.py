import copy
import unittest

from terminal_tun.singbox import generate_config
from terminal_tun.state import DEFAULT_STATE, add_outbound


class SingBoxConfigTests(unittest.TestCase):
    def test_generate_rules_config_routes_selected_domains(self):
        state = copy.deepcopy(DEFAULT_STATE)
        state["subscriptions"] = {}
        state["outbounds"] = {}
        state["rules"] = {
            "domains": [],
            "domain_suffixes": ["example.com"],
            "domain_keywords": [],
            "process_names": ["chrome.exe"],
            "process_paths": [],
        }
        add_outbound(state, "node", {"type": "socks", "server": "127.0.0.1", "server_port": 1080}, "manual")

        config = generate_config(state, target_platform="linux")

        self.assertEqual(config["dns"]["final"], "local")
        self.assertTrue(any(server["type"] == "local" and server["tag"] == "local" for server in config["dns"]["servers"]))
        self.assertTrue(any(server["type"] == "tcp" and server["tag"] == "cloudflare" for server in config["dns"]["servers"]))
        self.assertEqual(config["route"]["default_domain_resolver"], "cloudflare")
        self.assertEqual(config["route"]["final"], "direct")
        self.assertTrue(config["route"]["find_process"])
        self.assertNotIn("sniff", config["inbounds"][0])
        self.assertEqual(config["route"]["rules"][0], {"inbound": ["mixed-in", "tun-in"], "action": "sniff"})
        self.assertIn({"port": 53, "action": "hijack-dns"}, config["route"]["rules"])
        self.assertIn({"network": "udp", "port": 443, "action": "reject"}, config["route"]["rules"])
        self.assertTrue(
            any(rule.get("domain_suffix") == ["example.com"] and rule["outbound"] == "node" for rule in config["route"]["rules"])
        )
        self.assertIn({"domain_suffix": ["example.com"], "server": "cloudflare"}, config["dns"]["rules"])
        self.assertTrue(any(inbound["type"] == "tun" and inbound.get("auto_redirect") is True for inbound in config["inbounds"]))

    def test_generate_config_normalizes_saved_reality_nodes(self):
        state = copy.deepcopy(DEFAULT_STATE)
        state["outbounds"] = {}
        add_outbound(
            state,
            "reality",
            {
                "type": "vless",
                "server": "example.com",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "tls": {"enabled": True, "reality": {"enabled": True, "public_key": "public-key"}},
            },
            "manual",
        )

        config = generate_config(state)

        self.assertEqual(config["outbounds"][0]["tls"]["utls"], {"enabled": True, "fingerprint": "chrome"})

    def test_generate_windows_all_config_uses_urltest_without_sniff(self):
        state = copy.deepcopy(DEFAULT_STATE)
        state["mode"] = "all"
        state["selected_outbound"] = "auto"
        state["outbounds"] = {}
        add_outbound(state, "node", {"type": "socks", "server": "127.0.0.1", "server_port": 1080}, "manual")

        config = generate_config(state, target_platform="windows")

        self.assertEqual(config["route"]["final"], "auto")
        self.assertEqual(config["inbounds"][1]["mtu"], 1500)
        self.assertTrue(any(outbound["type"] == "urltest" and outbound["tag"] == "auto" for outbound in config["outbounds"]))
        self.assertNotIn({"inbound": ["mixed-in", "tun-in"], "action": "sniff"}, config["route"]["rules"])
        self.assertIn({"ip_is_private": True, "port": 7680, "action": "reject"}, config["route"]["rules"])
        self.assertIn({"network": "udp", "port": 443, "action": "reject"}, config["route"]["rules"])

    def test_generate_windows_config_respects_lower_mtu(self):
        state = copy.deepcopy(DEFAULT_STATE)
        state["tun"]["mtu"] = 1400
        state["outbounds"] = {}
        add_outbound(state, "node", {"type": "socks", "server": "127.0.0.1", "server_port": 1080}, "manual")

        config = generate_config(state, target_platform="windows")

        self.assertEqual(config["inbounds"][1]["mtu"], 1400)


if __name__ == "__main__":
    unittest.main()
