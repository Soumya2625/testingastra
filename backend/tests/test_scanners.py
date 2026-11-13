from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from app.rules import ALL_RULE_IDS, IAC_MATCHERS, IAC_RULES, SAST_RULES, SECRET_RULES
from app.scanners import docker_command, normalize_iac, normalize_sast, normalize_secret
from app.security import redact_text, sanitize_for_ai


class RuleCoverageTests(unittest.TestCase):
    def test_inventory_contains_all_36_configured_categories(self):
        self.assertEqual(len(SECRET_RULES), 14)
        self.assertEqual(len(IAC_RULES), 11)
        self.assertEqual(len(SAST_RULES), 11)
        self.assertEqual(len(ALL_RULE_IDS), 36)

    def test_scanner_configs_cover_all_secret_and_sast_rules(self):
        app_dir = Path(__file__).resolve().parents[1] / "app"
        secret_config = tomllib.loads((app_dir / "gitleaks.toml").read_text(encoding="utf-8"))
        configured_secrets = {f"secret.{rule['id']}" for rule in secret_config["rules"]}
        self.assertEqual(configured_secrets, {rule[0] for rule in SECRET_RULES})
        semgrep_text = (app_dir / "semgrep_rules.yml").read_text(encoding="utf-8")
        configured_sast = set(re.findall(r"^  - id: (astra-[a-z-]+)$", semgrep_text, re.MULTILINE))
        self.assertEqual(len(configured_sast), len(SAST_RULES) + 2)

    def test_secret_categories_normalize_and_mask_synthetic_values(self):
        for rule_id, _, severity in SECRET_RULES:
            with self.subTest(rule_id=rule_id):
                category = rule_id.removeprefix("secret.")
                finding = normalize_secret({
                    "RuleID": category,
                    "Description": "Synthetic credential test",
                    "Secret": "synthetic-secret-value-never-return-this",
                    "File": "config/example.env",
                    "StartLine": 7,
                })
                self.assertEqual(finding["rule_id"], rule_id)
                self.assertEqual(finding["severity"], severity)
                self.assertEqual(finding["file_path"], "config/example.env")
                self.assertEqual(finding["line"], 7)
                self.assertEqual(finding["evidence"], "[REDACTED]")
                self.assertNotIn("synthetic-secret-value-never-return-this", str(finding))

    def test_iac_categories_map_synthetic_checkov_results(self):
        for category, terms in IAC_MATCHERS:
            with self.subTest(category=category):
                finding = normalize_iac({
                    "check_name": f"Synthetic check {terms[0]}",
                    "check_id": "CKV_TEST_1",
                    "file_path": "infra/main.tf",
                    "file_line_range": [13, 13],
                    "resource": "synthetic_resource",
                    "guideline": "Set a secure value.",
                    "severity": "HIGH",
                })
                self.assertIsNotNone(finding)
                self.assertEqual(finding["rule_id"], f"iac.{category}")
                self.assertEqual(finding["file_path"], "infra/main.tf")
                self.assertEqual(finding["line"], 13)

    def test_sast_categories_map_semgrep_ids_and_cwe(self):
        expected = {
            "astra-sql-injection": ("sast.sql_injection", "CWE-89"),
            "astra-command-injection": ("sast.command_injection", "CWE-78"),
            "astra-xss": ("sast.xss", "CWE-79"),
            "astra-path-traversal": ("sast.path_traversal", "CWE-22"),
            "astra-ssrf": ("sast.ssrf", "CWE-918"),
            "astra-insecure-deserialization": ("sast.insecure_deserialization", "CWE-502"),
            "astra-weak-crypto": ("sast.weak_crypto", "CWE-327"),
            "astra-insecure-auth": ("sast.insecure_authentication", "CWE-287"),
            "astra-missing-authorization": ("sast.missing_authorization", "CWE-862"),
            "astra-unsafe-file-operation": ("sast.unsafe_file_operation", "CWE-73"),
            "astra-dynamic-execution": ("sast.dynamic_execution", "CWE-95"),
        }
        for check_id, (rule_id, cwe) in expected.items():
            with self.subTest(check_id=check_id):
                finding = normalize_sast({
                    "check_id": f"/config/semgrep_rules.yml.{check_id}",
                    "path": "src/example.py",
                    "start": {"line": 23},
                    "end": {"line": 24},
                    "extra": {"severity": "ERROR", "message": "Synthetic source-to-sink example"},
                })
                self.assertEqual(finding["rule_id"], rule_id)
                self.assertEqual(finding["cwe"], cwe)
                self.assertEqual(finding["severity"], "high")
                self.assertEqual(finding["verification_status"], "potential")
                self.assertEqual(finding["line"], 23)


class SanitizationTests(unittest.TestCase):
    def test_secret_like_values_are_redacted_before_persistence_or_ai(self):
        samples = [
            "AWS key AKIA0000000000000000",
            "github token ghp_aaaaaaaaaaaaaaaaaaaaaaaa",
            "config password=synthetic-password-value",
            "db postgres://user:synthetic-password@db.example/test",
            "JWT secret: synthetic-jwt-signing-secret-value",
        ]
        for sample in samples:
            with self.subTest(sample=sample):
                safe = redact_text(sample)
                self.assertNotIn("synthetic-password", safe)
                self.assertNotIn("synthetic-jwt-signing-secret-value", safe)
                self.assertNotIn("ghp_aaaaaaaa", safe)
                self.assertNotIn("AKIA0000000000000000", safe)
        self.assertEqual(
            sanitize_for_ai({"description": "Safe", "evidence": "raw", "credential": "raw"}),
            {"description": "Safe", "evidence": "[REDACTED]", "credential": "[REDACTED]"},
        )

    def test_scanner_commands_are_network_isolated_and_resource_limited(self):
        with patch("app.scanners.shutil.which", return_value="docker"):
            for scanner in ("secrets", "iac", "sast"):
                with self.subTest(scanner=scanner):
                    command = docker_command(scanner, Path("synthetic-repository"))
                    self.assertIn("--network", command)
                    self.assertIn("none", command)
                    self.assertIn("--memory", command)
                    self.assertIn("--cpus", command)
                    self.assertIn("--pids-limit", command)
                    self.assertIn("--read-only", command)
                    self.assertIn("--cap-drop", command)
                    self.assertNotIn("p/security-audit", command)


if __name__ == "__main__":
    unittest.main()
