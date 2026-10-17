import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCANNER = Path(__file__).resolve().parents[1] / "Sentinel.PY"


class SentinelCliTests(unittest.TestCase):
    def run_scanner(self, target, *args):
        return subprocess.run(
            [sys.executable, str(SCANNER), str(target), *args],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_reports_risks_without_printing_secret_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "app.py"
            source = ("pass" + 'word = "very-secret-value-123"\n') + (
                "os." + "system(user_input)\n"
            )
            target.write_text(
                source,
                encoding="utf-8",
            )

            result = self.run_scanner(target, "--format", "json")

            self.assertEqual(result.returncode, 1)
            report = json.loads(result.stdout)
            self.assertEqual(
                {finding["rule_id"] for finding in report["findings"]},
                {"HARDCODED-SECRET", "OS-SYSTEM"},
            )
            self.assertNotIn("very-secret-value-123", result.stdout)

    def test_excludes_files_and_applies_severity_threshold(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app.py").write_text("DEBUG = True\n", encoding="utf-8")
            (root / "ignored.py").write_text("os.system(value)\n", encoding="utf-8")

            result = self.run_scanner(root, "--exclude", "ignored.py", "--severity", "high")

            self.assertEqual(result.returncode, 0)
            self.assertIn("DEBUG-ENABLED", result.stdout)
            self.assertNotIn("OS-SYSTEM", result.stdout)

    def test_json_reports_private_key_as_critical(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "config.pem"
            target.write_text(
                "-----BEGIN " + "PRIVATE KEY-----\nredacted\n",
                encoding="utf-8",
            )

            result = self.run_scanner(target, "--format", "json")

            self.assertEqual(result.returncode, 1)
            report = json.loads(result.stdout)
            self.assertEqual(report["findings"][0]["severity"], "critical")
            self.assertNotIn("redacted", result.stdout)


if __name__ == "__main__":
    unittest.main()
