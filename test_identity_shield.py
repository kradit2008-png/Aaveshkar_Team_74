#!/usr/bin/env python3
"""
Unit tests for IdentityShield toolkit.
"""

import datetime
import os
import tempfile
import unittest
from pathlib import Path

from src.identity_shield import IdentityShield, sanitize_slug


class TestIdentityShield(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_vault.db"
        self.shield = IdentityShield(db_path=self.db_path, master_key="test_master_secret_key_12345")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sanitize_slug(self):
        self.assertEqual(sanitize_slug("Acme Software Inc."), "acme-software-inc")
        self.assertEqual(sanitize_slug("New York Times!!"), "new-york-times")
        self.assertEqual(sanitize_slug("   "), "service")

    def test_generate_alias_commercial(self):
        record = self.shield.generate_alias(
            service_name="CloudHost Pro",
            tier="commercial",
            target_email="primary@user.me",
            relay_domain="relay.shield.net",
        )
        self.assertTrue(record.alias_email.startswith("cloudhost-pro."))
        self.assertTrue(record.alias_email.endswith("@relay.shield.net"))
        self.assertEqual(record.status, "ACTIVE")
        self.assertEqual(record.tier, "commercial")
        self.assertEqual(record.target_forward_email, "primary@user.me")
        self.assertIsNone(record.expires_at)

    def test_generate_alias_ephemeral_ttl(self):
        record = self.shield.generate_alias(
            service_name="Shady Webinar",
            tier="ephemeral",
            ttl_days=7,
        )
        self.assertEqual(record.tier, "ephemeral")
        self.assertIsNotNone(record.expires_at)
        created_dt = datetime.datetime.fromisoformat(record.created_at)
        expires_dt = datetime.datetime.fromisoformat(record.expires_at)
        self.assertAlmostEqual((expires_dt - created_dt).days, 7, delta=1)

    def test_inbound_trace_authorized(self):
        record = self.shield.generate_alias(
            service_name="GitHub Enterprise",
            tier="commercial",
        )
        result = self.shield.trace_inbound_message(
            alias_email=record.alias_email,
            sender_email="support@github.com",
        )
        self.assertTrue(result["authorized"])
        self.assertEqual(result["verdict"], "FORWARD_ALLOWED")

    def test_inbound_trace_leak_detected_and_killswitch(self):
        record = self.shield.generate_alias(
            service_name="Conference Expo 2026",
            tier="ephemeral",
        )
        # Sender is an unsolicited marketing brokerage
        result = self.shield.trace_inbound_message(
            alias_email=record.alias_email,
            sender_email="promotions@spamdata-harvester.com",
            auto_revoke_on_leak=True,
        )
        self.assertFalse(result["authorized"])
        self.assertEqual(result["verdict"], "POTENTIAL_LEAK_OR_RESALE")
        self.assertEqual(result["forwarding_action"], "KILLED")

        # Now test that subsequent messages are completely dropped
        subsequent = self.shield.trace_inbound_message(
            alias_email=record.alias_email,
            sender_email="attacker@phish.com",
        )
        self.assertFalse(subsequent["authorized"])
        self.assertEqual(subsequent["verdict"], "BLOCKED_REVOKED")

    def test_manual_revocation(self):
        record = self.shield.generate_alias(service_name="Promo Store")
        revoked = self.shield.revoke_alias(record.alias_email, reason="UNSUBSCRIBE_FAILED_SPAM")
        self.assertEqual(revoked.status, "REVOKED")
        self.assertEqual(revoked.revocation_reason, "UNSUBSCRIBE_FAILED_SPAM")

    def test_list_and_filter(self):
        self.shield.generate_alias("Service A", tier="commercial")
        self.shield.generate_alias("Service B", tier="ephemeral")
        self.shield.generate_alias("Bank Core", tier="core")

        all_records = self.shield.list_identities()
        self.assertEqual(len(all_records), 3)

        ephemeral_records = self.shield.list_identities(tier="ephemeral")
        self.assertEqual(len(ephemeral_records), 1)
        self.assertEqual(ephemeral_records[0].service_name, "Service B")

    def test_search_identities(self):
        self.shield.generate_alias("Digital Ocean Cloud", tier="commercial")
        self.shield.generate_alias("AWS Cloud Services", tier="commercial")
        self.shield.generate_alias("Local Gym", tier="ephemeral")

        results = self.shield.search_identities("cloud")
        self.assertEqual(len(results), 2)
        service_names = {r.service_name for r in results}
        self.assertIn("Digital Ocean Cloud", service_names)
        self.assertIn("AWS Cloud Services", service_names)

    def test_verify_alias_authenticity(self):
        record = self.shield.generate_alias("Legit Corp", tier="commercial")
        self.assertTrue(self.shield.verify_alias_authenticity(record.alias_email))
        # Tampered alias
        tampered = record.alias_email.replace("legit-corp.", "forged-corp.")
        self.assertFalse(self.shield.verify_alias_authenticity(tampered))

    def test_purge_expired(self):
        record = self.shield.generate_alias("Temporary Sign-up", tier="ephemeral", ttl_days=1)
        # Force expiry to the past
        past_dt = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)).isoformat()
        self.shield._execute("UPDATE identities SET expires_at = ? WHERE id = ?", (past_dt, record.id))

        purged_count = self.shield.purge_expired()
        self.assertEqual(purged_count, 1)

        updated = self.shield.get_identity_by_id(record.id)
        self.assertEqual(updated.status, "EXPIRED")

    def test_reset_demo(self):
        created = self.shield.reset_demo()
        self.assertGreaterEqual(len(created), 5)
        identities = self.shield.list_identities()
        self.assertEqual(len(identities), len(created))

    def test_scan_threat_intelligence(self):
        record = self.shield.generate_alias("Test SaaS", tier="commercial")
        result = self.shield.scan_threat_intelligence(record.alias_email)
        self.assertEqual(result["alias_email"], record.alias_email)
        self.assertIn(result["exposure_level"], ["MINIMAL", "ELEVATED", "CRITICAL"])
        self.assertTrue(len(result["matched_broker_networks"]) > 0)

    def test_compute_ppid_proof(self):
        proof = self.shield.compute_ppid_proof("alice@example.com")
        self.assertEqual(proof["canonical_email"], "alice@example.com")
        self.assertFalse(proof["collusion_linkable"])
        self.assertNotEqual(proof["client_a"]["ppid"], proof["client_b"]["ppid"])


if __name__ == "__main__":
    unittest.main()
