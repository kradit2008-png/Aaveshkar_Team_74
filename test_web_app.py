#!/usr/bin/env python3
"""
Integration tests for Identity Shield Flask web application.
"""

import json
import tempfile
import unittest
from pathlib import Path

from web.app import create_app


class TestWebApp(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_web_vault.db"
        self.app = create_app(db_path=self.db_path, test_config={"TESTING": True})
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_index_route(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"IDENTITY SHIELD", response.data)
        self.assertIn(b"Identity Vault", response.data)

    def test_api_stats_initial(self):
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["total_identities"], 0)
        self.assertEqual(data["active"], 0)
        self.assertEqual(data["leaks_detected"], 0)

    def test_create_alias_and_stats(self):
        # Create commercial alias
        payload = {
            "service_name": "Test Platform",
            "service_domain": "testplatform.com",
            "tier": "commercial",
            "target_forward_email": "real@domain.com",
        }
        res = self.client.post("/api/aliases", data=json.dumps(payload), content_type="application/json")
        self.assertEqual(res.status_code, 201)
        created = res.get_json()
        self.assertEqual(created["service_name"], "Test Platform")
        self.assertEqual(created["status"], "ACTIVE")

        # Verify stats updated
        stats_res = self.client.get("/api/stats")
        stats = stats_res.get_json()
        self.assertEqual(stats["total_identities"], 1)
        self.assertEqual(stats["active"], 1)

    def test_create_alias_validation(self):
        # Missing service_name
        res = self.client.post("/api/aliases", data=json.dumps({}), content_type="application/json")
        self.assertEqual(res.status_code, 400)

    def test_revoke_alias(self):
        # Create alias first
        create_res = self.client.post(
            "/api/aliases",
            data=json.dumps({"service_name": "Spam Service", "tier": "ephemeral"}),
            content_type="application/json",
        )
        alias_email = create_res.get_json()["alias_email"]

        # Revoke it
        revoke_res = self.client.post(
            f"/api/aliases/{alias_email}/revoke",
            data=json.dumps({"reason": "TEST_REVOCATION"}),
            content_type="application/json",
        )
        self.assertEqual(revoke_res.status_code, 200)
        revoked_data = revoke_res.get_json()
        self.assertEqual(revoked_data["status"], "REVOKED")
        self.assertEqual(revoked_data["revocation_reason"], "TEST_REVOCATION")

    def test_trace_inbound_and_leak_detection(self):
        # Create alias
        create_res = self.client.post(
            "/api/aliases",
            data=json.dumps({
                "service_name": "SecureBank",
                "service_domain": "securebank.com",
                "tier": "commercial",
            }),
            content_type="application/json",
        )
        alias_email = create_res.get_json()["alias_email"]

        # Authorized trace
        trace_ok = self.client.post(
            "/api/trace",
            data=json.dumps({
                "alias_email": alias_email,
                "sender_email": "alerts@securebank.com",
                "auto_revoke": False,
            }),
            content_type="application/json",
        )
        self.assertEqual(trace_ok.status_code, 200)
        self.assertEqual(trace_ok.get_json()["verdict"], "FORWARD_ALLOWED")

        # Leak trace with auto-revoke
        trace_leak = self.client.post(
            "/api/trace",
            data=json.dumps({
                "alias_email": alias_email,
                "sender_email": "phishing@malicious-spammer.org",
                "auto_revoke": True,
            }),
            content_type="application/json",
        )
        self.assertEqual(trace_leak.status_code, 200)
        self.assertEqual(trace_leak.get_json()["verdict"], "POTENTIAL_LEAK_OR_RESALE")
        self.assertEqual(trace_leak.get_json()["forwarding_action"], "KILLED")

    def test_export_vault(self):
        # Create an alias
        self.client.post(
            "/api/aliases",
            data=json.dumps({"service_name": "ExportService"}),
            content_type="application/json",
        )
        res = self.client.get("/api/export")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "application/json")
        data = json.loads(res.data.decode("utf-8"))
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["service_name"], "ExportService")


if __name__ == "__main__":
    unittest.main()
