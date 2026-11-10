"""Tests for secrets_scanner. Run with: python -m unittest -v

Every fake credential is assembled at runtime, so this file contains no
string that looks like a real secret.
"""
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import secrets_scanner as ss

FAKE_AWS = "AKIA" + "Q7Z2M4K9T1X8B6N3"
FAKE_GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
FAKE_GOOGLE = "AIza" + "Sy" + "D4k9Lm2Qx7Vb1Nc8Zt5Rw3Jh6Gf0Ps4Yu"
FAKE_TELEGRAM = "123456789:" + "AAH" + "k9Lm2Qx7Vb1Nc8Zt5Rw3Jh6Gf0Ps4Yu_"
FAKE_PASSWORD = "T9#kLm2$Qx7!Vb1"
PEM_HEADER = "-----BEGIN RSA " + "PRIVATE KEY-----"


def ids(findings):
    return [f.rule_id for f in findings]


class RuleTests(unittest.TestCase):
    def test_aws_key(self):
        self.assertEqual(ids(ss.scan_text(f"key = {FAKE_AWS}", "a.py")), ["aws-access-key"])

    def test_github_token(self):
        self.assertEqual(ids(ss.scan_text(f"GH={FAKE_GITHUB}", ".env")), ["github-token"])

    def test_google_key(self):
        self.assertEqual(ids(ss.scan_text(f"url?key={FAKE_GOOGLE}", "a.js")), ["google-api-key"])

    def test_telegram_token(self):
        self.assertEqual(ids(ss.scan_text(f"BOT = '{FAKE_TELEGRAM}'", "bot.py")), ["telegram-bot-token"])

    def test_private_key(self):
        self.assertEqual(ids(ss.scan_text(PEM_HEADER, "id_rsa")), ["private-key"])

    def test_database_url(self):
        url = "postgres://admin:" + "s3cr3tPassw0rd" + "@db.internal:5432/app"
        self.assertEqual(ids(ss.scan_text(url, "settings.py")), ["db-url-password"])

    def test_generic_password(self):
        self.assertEqual(ids(ss.scan_text(f'db_password = "{FAKE_PASSWORD}"', "c.py")), ["generic-secret"])

    def test_specific_rule_wins_over_generic(self):
        found = ss.scan_text(f'api_key = "{FAKE_GOOGLE}"', "c.py")
        self.assertEqual(ids(found), ["google-api-key"])


class FalsePositiveTests(unittest.TestCase):
    def test_placeholder_is_ignored(self):
        self.assertEqual(ss.scan_text('password = "your_password_here"', "c.py"), [])

    def test_low_entropy_is_ignored(self):
        self.assertEqual(ss.scan_text('password = "aaaaaaaaaaaa"', "c.py"), [])

    def test_env_lookup_is_ignored(self):
        self.assertEqual(ss.scan_text('token = os.environ["API_TOKEN"]', "c.py"), [])

    def test_template_string_is_ignored(self):
        self.assertEqual(ss.scan_text('password = "{DB_PASSWORD}"', "c.py"), [])
        self.assertEqual(ss.scan_text('token = "${API_TOKEN}"', "c.sh"), [])

    def test_inline_ignore(self):
        self.assertEqual(ss.scan_text(f"key = {FAKE_AWS}  # nosecret", "a.py"), [])

    def test_line_numbers(self):
        found = ss.scan_text(f"a = 1\nb = 2\nkey = {FAKE_AWS}\n", "a.py")
        self.assertEqual(found[0].line, 3)


class RedactionTests(unittest.TestCase):
    def test_full_secret_never_printed(self):
        found = ss.scan_text(f"key = {FAKE_AWS}", "a.py")
        self.assertNotIn(FAKE_AWS, found[0].preview)
        self.assertTrue(found[0].preview.startswith("AKIA"))
        self.assertNotIn(FAKE_AWS, ss.format_text(found, color=False))

    def test_entropy(self):
        self.assertEqual(ss.shannon_entropy("aaaa"), 0.0)
        self.assertGreater(ss.shannon_entropy(FAKE_PASSWORD), 3.0)


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                   check=True, capture_output=True)


class RepoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        git(self.repo, "init", "-q")

    def tearDown(self):
        self.tmp.cleanup()

    def test_tree_scan_and_ignore_file(self):
        (self.repo / "app.py").write_text(f"KEY = '{FAKE_AWS}'\n")
        (self.repo / "fixtures").mkdir()
        (self.repo / "fixtures" / "sample.txt").write_text(f"{FAKE_GITHUB}\n")
        self.assertEqual(sorted(ids(ss.scan_tree(self.repo))), ["aws-access-key", "github-token"])
        (self.repo / ".secretsignore").write_text("# test data\nfixtures/\n")
        self.assertEqual(ids(ss.scan_tree(self.repo)), ["aws-access-key"])

    def test_history_finds_deleted_secret(self):
        cfg = self.repo / "config.py"
        cfg.write_text(f"KEY = '{FAKE_AWS}'\n")
        git(self.repo, "add", "."); git(self.repo, "commit", "-qm", "add config")
        cfg.write_text("KEY = os.environ['KEY']\n")
        git(self.repo, "add", "."); git(self.repo, "commit", "-qm", "remove key")
        self.assertEqual(ss.scan_tree(self.repo), [])
        history = ss.scan_history(self.repo)
        self.assertEqual(ids(history), ["aws-access-key"])
        self.assertEqual(history[0].file, "config.py")
        self.assertEqual(history[0].line, 1)
        self.assertTrue(history[0].commit)

    def test_binary_files_are_skipped(self):
        (self.repo / "blob.bin").write_bytes(b"\0\0" + FAKE_AWS.encode())
        self.assertEqual(ss.scan_tree(self.repo), [])

    def test_cli_exit_codes_and_json(self):
        out = StringIO()
        with redirect_stdout(out):
            self.assertEqual(ss.main([str(self.repo)]), 0)
        (self.repo / "app.py").write_text(f'password = "{FAKE_PASSWORD}"\n')
        out = StringIO()
        with redirect_stdout(out):
            self.assertEqual(ss.main([str(self.repo), "--json"]), 1)
        data = json.loads(out.getvalue())
        self.assertEqual(data[0]["rule_id"], "generic-secret")
        with redirect_stdout(StringIO()):
            self.assertEqual(ss.main([str(self.repo), "--fail-on", "high"]), 0)


if __name__ == "__main__":
    unittest.main()
