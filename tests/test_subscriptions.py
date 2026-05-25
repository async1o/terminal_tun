import base64
import json
import unittest

from terminal_tun.subscriptions import parse_proxy_uri, parse_subscription_payload


class SubscriptionParsingTests(unittest.TestCase):
    def test_parse_shadowsocks_uri(self):
        encoded = base64.urlsafe_b64encode(b"2022-blake3-aes-128-gcm:secret@example.com:8388").decode().rstrip("=")

        outbound = parse_proxy_uri(f"ss://{encoded}#Home")

        self.assertEqual(outbound["type"], "shadowsocks")
        self.assertEqual(outbound["server"], "example.com")
        self.assertEqual(outbound["server_port"], 8388)
        self.assertEqual(outbound["method"], "2022-blake3-aes-128-gcm")
        self.assertEqual(outbound["password"], "secret")

    def test_parse_base64_subscription(self):
        payload = "trojan://pass@example.com:443?security=tls&sni=example.com#Node"
        encoded = base64.b64encode(payload.encode()).decode()

        outbounds = parse_subscription_payload(encoded, "demo")

        self.assertEqual(len(outbounds), 1)
        self.assertEqual(outbounds[0]["type"], "trojan")
        self.assertTrue(outbounds[0]["tls"]["enabled"])

    def test_parse_singbox_json_outbounds(self):
        payload = json.dumps(
            {
                "outbounds": [
                    {"type": "direct", "tag": "direct"},
                    {"type": "socks", "tag": "node", "server": "127.0.0.1", "server_port": 1080},
                ]
            }
        )

        outbounds = parse_subscription_payload(payload, "json")

        self.assertEqual(len(outbounds), 1)
        self.assertEqual(outbounds[0]["type"], "socks")

    def test_parse_json_remark_as_display_name(self):
        payload = json.dumps(
            {
                "outbounds": [
                    {
                        "type": "socks",
                        "tag": "internal",
                        "Remark": "🇳🇱 Test Node",
                        "server": "127.0.0.1",
                        "server_port": 1080,
                    }
                ]
            }
        )

        outbounds = parse_subscription_payload(payload, "json")

        self.assertEqual(outbounds[0]["_display_name"], "🇳🇱 Test Node")
        self.assertNotIn("Remark", outbounds[0])

    def test_parse_reality_vless_adds_utls(self):
        uri = (
            "vless://00000000-0000-0000-0000-000000000000@example.com:443"
            "?security=reality&sni=www.example.com&fp=chrome&pbk=public-key&sid=abcd#Reality"
        )

        outbound = parse_proxy_uri(uri)

        self.assertEqual(outbound["type"], "vless")
        self.assertEqual(outbound["tls"]["utls"]["fingerprint"], "chrome")
        self.assertTrue(outbound["tls"]["reality"]["enabled"])


if __name__ == "__main__":
    unittest.main()
