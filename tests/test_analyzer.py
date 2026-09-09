import unittest

from src.analyzer import analyze, posture_score
from src.models import Grant, Principal


class AnalyzerTests(unittest.TestCase):
    def test_privileged_user_without_mfa_is_critical(self):
        p = Principal("u1", "user", "Admin", "aws", mfa_enabled=False)
        g = Grant("g1", "u1", "acct", "admin", "account", privileged=True)
        findings = analyze([p], [g])
        self.assertTrue(any(f.control_id == "IAM-001" and f.severity == "critical" for f in findings))

    def test_wildcard_grant_is_high(self):
        p = Principal("u1", "user", "Admin", "aws", mfa_enabled=True)
        g = Grant("g1", "u1", "acct", "*", "account", privileged=True, wildcard=True)
        findings = analyze([p], [g])
        self.assertTrue(any(f.control_id == "IAM-002" for f in findings))

    def test_dormant_privileged_identity(self):
        p = Principal("u1", "user", "Dormant", "azure", mfa_enabled=True, last_used_days=120)
        g = Grant("g1", "u1", "sub", "Owner", "subscription", privileged=True)
        findings = analyze([p], [g])
        self.assertTrue(any(f.control_id == "IAM-004" for f in findings))

    def test_old_service_account_credential(self):
        p = Principal("s1", "service_account", "Bot", "gcp", credential_age_days=200, owner="Platform")
        findings = analyze([p], [])
        self.assertTrue(any(f.control_id == "IAM-005" for f in findings))

    def test_external_privileged_principal(self):
        p = Principal("u1", "user", "Vendor", "azure", mfa_enabled=True, external=True, owner="Infra")
        g = Grant("g1", "u1", "sub", "Contributor", "subscription", privileged=True)
        findings = analyze([p], [g])
        self.assertTrue(any(f.control_id == "IAM-007" for f in findings))

    def test_unknown_grant_principal_rejected(self):
        g = Grant("g1", "missing", "acct", "read", "account")
        with self.assertRaises(ValueError):
            analyze([], [g])

    def test_duplicate_principal_rejected(self):
        p1 = Principal("u1", "user", "One", "aws")
        p2 = Principal("u1", "user", "Two", "aws")
        with self.assertRaises(ValueError):
            analyze([p1, p2], [])

    def test_posture_score_declines_with_findings(self):
        p = Principal("u1", "user", "Admin", "aws", mfa_enabled=False)
        g = Grant("g1", "u1", "acct", "admin", "account", privileged=True, wildcard=True)
        findings = analyze([p], [g])
        self.assertLess(posture_score(findings), 100)


if __name__ == "__main__":
    unittest.main()
