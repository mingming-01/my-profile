import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app import create_app


ORIGIN = "http://localhost:5000"


class PasskeySecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.temp_dir.name) / "test.sqlite3")
        self.app = create_app(
            {
                "TESTING": True,
                "APP_ENV": "testing",
                "SECRET_KEY": "test-only-secret-key-with-enough-length-000000",
                "WEBAUTHN_RP_ID": "localhost",
                "WEBAUTHN_ORIGIN": ORIGIN,
                "DATABASE_PATH": self.database_path,
                "PASSKEY_INVITE_TOKENS": {
                    "account-a": "A" * 40,
                    "account-b": "B" * 40,
                },
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def post(self, path, payload=None, include_origin=True):
        headers = {"Origin": ORIGIN} if include_origin else {}
        return self.client.post(path, json=payload, headers=headers)

    def db_connect(self):
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def test_private_endpoints_require_authentication(self):
        self.assertEqual(self.client.get("/api/private").status_code, 401)
        self.assertEqual(self.client.get("/api/passkeys").status_code, 401)
        self.assertEqual(
            self.client.delete("/api/passkeys/1", headers={"Origin": ORIGIN}).status_code,
            401,
        )
        self.assertEqual(self.client.get("/private").status_code, 302)

    def test_mutating_api_rejects_missing_or_wrong_origin(self):
        missing = self.post(
            "/api/passkey/register/options",
            {"username": "account-a"},
            include_origin=False,
        )
        wrong = self.client.post(
            "/api/logout",
            headers={"Origin": "https://attacker.invalid"},
        )
        self.assertEqual(missing.status_code, 403)
        self.assertEqual(wrong.status_code, 403)

    def test_initial_registration_requires_invitation_token(self):
        missing = self.post(
            "/api/passkey/register/options",
            {
                "username": "account-a",
                "display_name": "Account A",
                "passkey_name": "My laptop",
            },
        )
        invalid = self.post(
            "/api/passkey/register/options",
            {
                "username": "account-a",
                "display_name": "Account A",
                "passkey_name": "My laptop",
                "invite_token": "incorrect",
            },
        )
        self.assertEqual(missing.status_code, 403)
        self.assertEqual(invalid.status_code, 403)

        with self.app.app_context():
            row = self.db_connect().execute(
                "SELECT username FROM users WHERE username = 'account-a'"
            ).fetchone()
            self.assertIsNone(row)

    def test_valid_invitation_creates_options_but_not_user_before_verification(self):
        response = self.post(
            "/api/passkey/register/options",
            {
                "username": "account-a",
                "display_name": "Account A",
                "passkey_name": "My laptop",
                "invite_token": "A" * 40,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("challenge", response.get_json())

        connection = self.db_connect()
        try:
            row = connection.execute(
                "SELECT username FROM users WHERE username = 'account-a'"
            ).fetchone()
            self.assertIsNone(row)
        finally:
            connection.close()

    @patch("app.verify_registration_response")
    def test_invitation_is_one_time_and_successful_registration_logs_in(self, verify_mock):
        verify_mock.return_value = SimpleNamespace(
            credential_id=b"test-credential-id",
            credential_public_key=b"test-public-key",
            sign_count=0,
        )

        options = self.post(
            "/api/passkey/register/options",
            {
                "username": "account-a",
                "display_name": "Account A",
                "passkey_name": "First device",
                "invite_token": "A" * 40,
            },
        )
        self.assertEqual(options.status_code, 200)

        verified = self.post("/api/passkey/register/verify", {"id": "mock"})
        self.assertEqual(verified.status_code, 200)
        self.assertTrue(verified.get_json()["ok"])
        self.assertEqual(self.client.get("/api/private").status_code, 200)

        self.post("/api/logout", {})
        replay = self.post(
            "/api/passkey/register/options",
            {
                "username": "account-a",
                "display_name": "Account A",
                "passkey_name": "Second attempt",
                "invite_token": "A" * 40,
            },
        )
        self.assertEqual(replay.status_code, 409)

        connection = self.db_connect()
        try:
            total = connection.execute(
                "SELECT COUNT(*) AS total FROM passkeys WHERE username = 'account-a'"
            ).fetchone()["total"]
            self.assertEqual(total, 1)
        finally:
            connection.close()

    def test_expired_registration_challenge_is_rejected_and_consumed(self):
        with self.client.session_transaction() as browser_session:
            browser_session["registration"] = {
                "username": "account-a",
                "display_name": "Account A",
                "passkey_name": "Old challenge",
                "user_handle": "dXNlci1oYW5kbGU",
                "mode": "bootstrap",
                "challenge": "Y2hhbGxlbmdl",
                "issued_at": time.time() - 500,
            }

        response = self.post("/api/passkey/register/verify", {"id": "mock"})
        self.assertEqual(response.status_code, 400)

        with self.client.session_transaction() as browser_session:
            self.assertNotIn("registration", browser_session)

    def test_login_options_do_not_reveal_account_state(self):
        missing_account = self.post(
            "/api/passkey/login/options",
            {"username": "account-a"},
        )
        invalid_account = self.post(
            "/api/passkey/login/options",
            {"username": "not-an-account"},
        )
        self.assertEqual(missing_account.status_code, 401)
        self.assertEqual(invalid_account.status_code, 401)
        self.assertEqual(
            missing_account.get_json()["error"],
            invalid_account.get_json()["error"],
        )

    def test_last_passkey_cannot_be_deleted(self):
        connection = self.db_connect()
        try:
            connection.execute(
                """
                INSERT INTO users (username, display_name, user_handle, invite_used_at, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                ("account-a", "Account A", "dXNlci1oYW5kbGU", "2026-11-02T00:00:00+00:00", "2026-11-02T00:00:00+00:00"),
            )
            connection.execute(
                """
                INSERT INTO passkeys (credential_id, username, public_key, sign_count, name, registered_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                ("Y3JlZGVudGlhbA", "account-a", "cHVibGlj", 0, "Laptop", "2026-11-02T00:00:00+00:00"),
            )
            connection.commit()
        finally:
            connection.close()

        with self.client.session_transaction() as browser_session:
            browser_session["authenticated_user"] = "account-a"
            browser_session["authenticated_at"] = time.time()

        response = self.client.delete(
            "/api/passkeys/1",
            headers={"Origin": ORIGIN},
        )
        self.assertEqual(response.status_code, 409)

    def test_challenge_and_private_responses_are_not_cached(self):
        response = self.client.get("/private")
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("Cache-Control"), "no-store")

    def test_rate_limit_is_applied_to_login_options(self):
        responses = [
            self.post("/api/passkey/login/options", {"username": "account-a"})
            for _ in range(11)
        ]
        self.assertEqual(responses[-1].status_code, 429)

    def test_production_requires_secret_and_webauthn_origin(self):
        with self.assertRaises(RuntimeError):
            create_app(
                {
                    "APP_ENV": "production",
                    "SECRET_KEY": "",
                    "WEBAUTHN_RP_ID": "my-profile-ohhl.onrender.com",
                    "WEBAUTHN_ORIGIN": "https://my-profile-ohhl.onrender.com",
                    "DATABASE_PATH": self.database_path,
                    "PASSKEY_INVITE_TOKENS": {"account-a": "A" * 40},
                }
            )

    def test_private_template_does_not_insert_dynamic_values_with_inner_html(self):
        template_path = Path(__file__).resolve().parents[1] / "templates" / "private.html"
        template = template_path.read_text(encoding="utf-8")
        self.assertNotIn("innerHTML", template)
        self.assertIn("textContent", template)
        self.assertNotRegex(template, r"\bon(?:click|change|submit|input)\s*=")


if __name__ == "__main__":
    unittest.main()
