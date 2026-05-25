import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

from terminal_tun.cli import main
from terminal_tun.state import load_state


class ProfileCliTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.old_home = os.environ.get("TERMINAL_TUN_HOME")
        self.old_data = os.environ.get("TERMINAL_TUN_DATA")
        os.environ["TERMINAL_TUN_HOME"] = self.tempdir.name
        os.environ["TERMINAL_TUN_DATA"] = self.tempdir.name

    def tearDown(self):
        if self.old_home is None:
            os.environ.pop("TERMINAL_TUN_HOME", None)
        else:
            os.environ["TERMINAL_TUN_HOME"] = self.old_home
        if self.old_data is None:
            os.environ.pop("TERMINAL_TUN_DATA", None)
        else:
            os.environ["TERMINAL_TUN_DATA"] = self.old_data
        self.tempdir.cleanup()

    def run_cli(self, *args):
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            return main(list(args))

    def test_create_and_apply_profile(self):
        self.assertEqual(self.run_cli("init"), 0)
        self.assertEqual(
            self.run_cli(
                "profile",
                "create",
                "work",
                "--domain",
                "chatgpt.com",
                "--full-domain",
                "api.openai.com",
                "--keyword",
                "googlevideo",
                "--app",
                "chrome.exe",
            ),
            0,
        )
        self.assertEqual(self.run_cli("profile", "apply", "work"), 0)

        state = load_state()
        self.assertEqual(state["active_profile"], "work")
        self.assertEqual(state["mode"], "rules")
        self.assertIn("chatgpt.com", state["rules"]["domain_suffixes"])
        self.assertIn("api.openai.com", state["rules"]["domains"])
        self.assertIn("googlevideo", state["rules"]["domain_keywords"])
        self.assertIn("chrome.exe", state["rules"]["process_names"])

    def test_template_alias_and_saved_profile_mutation(self):
        self.assertEqual(self.run_cli("init"), 0)
        self.assertEqual(self.run_cli("template", "create", "streaming", "--domain", "youtube.com"), 0)
        self.assertEqual(self.run_cli("template", "apply", "streaming"), 0)
        self.assertEqual(self.run_cli("profile", "add-domain", "streaming", "googlevideo.com"), 0)
        self.assertEqual(self.run_cli("profile", "remove-domain", "streaming", "youtube.com"), 0)

        state = load_state()
        self.assertEqual(state["active_profile"], "streaming")
        self.assertIn("googlevideo.com", state["rules"]["domain_suffixes"])
        self.assertNotIn("youtube.com", state["rules"]["domain_suffixes"])

    def test_background_status_without_process(self):
        self.assertEqual(self.run_cli("init"), 0)
        self.assertEqual(self.run_cli("background", "status"), 0)
        self.assertEqual(self.run_cli("bg", "status"), 0)


if __name__ == "__main__":
    unittest.main()
