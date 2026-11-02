import hashlib
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app import _validate_runtime_config, create_app


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

        connection = self.db_connect()
        try:
            row = connection.execute(
                "SELECT username FROM users WHERE username = 'account-a'"
            ).fetchone()
            self.assertIsNone(row)
        finally:
            connection.close()

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

        with self.client.session_transaction() as browser_session:
            original_challenge_hash = browser_session["registration"]["challenge_hash"]

        verified = self.post("/api/passkey/register/verify", {"id": "mock"})
        self.assertEqual(verified.status_code, 200)
        self.assertTrue(verified.get_json()["ok"])
        self.assertEqual(self.client.get("/api/private").status_code, 200)

        # Replaying an older signed session cookie must not resurrect a consumed challenge.
        with self.client.session_transaction() as browser_session:
            browser_session["registration"] = {"challenge_hash": original_challenge_hash}
        replayed_challenge = self.post("/api/passkey/register/verify", {"id": "mock"})
        self.assertEqual(replayed_challenge.status_code, 400)

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
        self.assertEqual(replay.status_code, 403)

        connection = self.db_connect()
        try:
            total = connection.execute(
                "SELECT COUNT(*) AS total FROM passkeys WHERE username = 'account-a'"
            ).fetchone()["total"]
            self.assertEqual(total, 1)
        finally:
            connection.close()

    def test_expired_registration_challenge_is_rejected(self):
        challenge_hash = hashlib.sha256(b"expired-challenge").hexdigest()
        connection = self.db_connect()
        try:
            connection.execute(
                """
                INSERT INTO webauthn_challenges
                    (challenge_hash, ceremony, challenge, username, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge_hash,
                    "registration",
                    "ZXhwaXJlZC1jaGFsbGVuZ2U",
                    "account-a",
                    "{}",
                    time.time() - 500,
                ),
            )
            connection.commit()
        finally:
            connection.close()

        with self.client.session_transaction() as browser_session:
            browser_session["registration"] = {"challenge_hash": challenge_hash}

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

    def _seed_account_with_passkey(self):
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
                ("Y3JlZC1pZA", "account-a", "cHVibGljLWtleQ", 0, "Laptop", "2026-11-02T00:00:00+00:00"),
            )
            connection.commit()
        finally:
            connection.close()

    def test_existing_account_cannot_add_passkey_without_recent_authentication(self):
        self._seed_account_with_passkey()
        response = self.post(
            "/api/passkey/register/options",
            {
                "username": "account-a",
                "display_name": "Account A",
                "passkey_name": "Another device",
                "invite_token": "A" * 40,
            },
        )
        self.assertEqual(response.status_code, 403)

        with self.client.session_transaction() as browser_session:
            browser_session["authenticated_user"] = "account-a"
            browser_session["authenticated_at"] = time.time() - 600

        stale = self.post(
            "/api/passkey/register/options",
            {
                "username": "account-a",
                "display_name": "Account A",
                "passkey_name": "Another device",
            },
        )
        self.assertEqual(stale.status_code, 403)

        with self.client.session_transaction() as browser_session:
            browser_session["authenticated_at"] = time.time()

        allowed = self.post(
            "/api/passkey/register/options",
            {
                "username": "account-a",
                "display_name": "Account A",
                "passkey_name": "Another device",
            },
        )
        self.assertEqual(allowed.status_code, 200)

    @patch("app.verify_authentication_response")
    def test_login_verification_updates_counter_and_creates_session(self, verify_mock):
        self._seed_account_with_passkey()
        verify_mock.return_value = SimpleNamespace(new_sign_count=1)

        options = self.post(
            "/api/passkey/login/options",
            {"username": "account-a"},
        )
        self.assertEqual(options.status_code, 200)

        result = self.post(
            "/api/passkey/login/verify",
            {"id": "Y3JlZC1pZA", "rawId": "Y3JlZC1pZA"},
        )
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.get_json()["ok"])
        self.assertEqual(self.client.get("/api/private").status_code, 200)

        connection = self.db_connect()
        try:
            counter = connection.execute(
                "SELECT sign_count FROM passkeys WHERE username = 'account-a'"
            ).fetchone()["sign_count"]
            self.assertEqual(counter, 1)
        finally:
            connection.close()

        replay = self.post(
            "/api/passkey/login/verify",
            {"id": "Y3JlZC1pZA", "rawId": "Y3JlZC1pZA"},
        )
        self.assertEqual(replay.status_code, 400)

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

    def test_production_requires_secret_tokens_origin_and_postgres_database(self):
        production_config = {
            "APP_ENV": "production",
            "SECRET_KEY": "S" * 64,
            "WEBAUTHN_RP_ID": "my-profile-ohhl.onrender.com",
            "WEBAUTHN_ORIGIN": "https://my-profile-ohhl.onrender.com",
            "PASSKEY_INVITE_TOKENS": {
                "account-a": "A" * 40,
                "account-b": "B" * 40,
            },
        }

        with self.assertRaises(RuntimeError):
            create_app({**production_config, "SECRET_KEY": ""})

        # A local SQLite path must not satisfy production database requirements.
        with self.assertRaises(RuntimeError):
            create_app({**production_config, "DATABASE_PATH": self.database_path})

        with self.assertRaises(RuntimeError):
            create_app({
                **production_config,
                "DATABASE_URL": "sqlite:///not-postgres",
            })

        with self.assertRaises(RuntimeError):
            _validate_runtime_config({
                **production_config,
                "DATABASE_URL": "postgresql://user:password@db.example.invalid:5432/postgres",
                "PASSKEY_INVITE_TOKENS": {"account-a": "A" * 40},
            })

        valid_config = {
            **production_config,
            "DATABASE_URL": "postgresql://user:password@db.example.invalid:5432/postgres",
        }
        _validate_runtime_config(valid_config)
        self.assertEqual(valid_config["DATABASE_URL"].split("@", 1)[1], "db.example.invalid:5432/postgres")

    def test_private_template_does_not_insert_dynamic_values_with_inner_html(self):
        template_path = Path(__file__).resolve().parents[1] / "templates" / "private.html"
        template = template_path.read_text(encoding="utf-8")
        self.assertNotIn("innerHTML", template)
        self.assertIn("textContent", template)
        self.assertNotRegex(template, r"\bon(?:click|change|submit|input)\s*=")


if __name__ == "__main__":
    unittest.main()
