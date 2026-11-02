import base64
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import time
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask,
    current_app,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)


BASE_DIR = Path(__file__).resolve().parent
ACCOUNT_NAMES = ("account-a", "account-b")
CHALLENGE_TTL_SECONDS = 180
RECENT_AUTH_SECONDS = 300
RATE_LIMIT_WINDOW_SECONDS = 300
RATE_LIMIT_MAX_ATTEMPTS = 10

PRIVATE_DATA = {
    "account-a": {
        "title": "Account A Private Space",
        "items": [
            "ALEPH 프로젝트 회고 메모",
            "지원 직무 후보 정리",
            "다음 프로젝트에서 개선할 점",
        ],
    },
    "account-b": {
        "title": "Account B Private Space",
        "items": [
            "가상의 프로젝트 메모 B",
            "가상의 지원 목표 B",
            "가상의 자기평가 B",
        ],
    },
}


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64d(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("잘못된 Base64URL 값입니다.")
    return base64url_to_bytes(value)


def now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _invite_tokens_from_env():
    raw = os.environ.get("PASSKEY_INVITE_TOKENS", "").strip()
    if not raw:
        return {}

    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("PASSKEY_INVITE_TOKENS는 유효한 JSON이어야 합니다.") from exc

    if not isinstance(value, dict):
        raise RuntimeError("PASSKEY_INVITE_TOKENS는 계정별 코드 객체여야 합니다.")

    normalized = {}
    for username, token in value.items():
        if username not in ACCOUNT_NAMES or not isinstance(token, str):
            raise RuntimeError("초대 코드는 account-a/account-b 계정에 문자열로 설정해야 합니다.")
        if len(token) < 32:
            raise RuntimeError("각 Passkey 초대 코드는 32자 이상이어야 합니다.")
        normalized[username] = token

    return normalized


def _validate_runtime_config(config):
    environment = config["APP_ENV"]
    secret_key = config.get("SECRET_KEY")
    rp_id = config.get("WEBAUTHN_RP_ID")
    origin = config.get("WEBAUTHN_ORIGIN")

    if environment == "production":
        if not secret_key or len(secret_key) < 32:
            raise RuntimeError("운영 환경에는 32자 이상의 FLASK_SECRET_KEY가 필요합니다.")
        if not rp_id or not origin:
            raise RuntimeError("운영 환경에는 WEBAUTHN_RP_ID와 WEBAUTHN_ORIGIN이 필요합니다.")
        invite_tokens = config.get("PASSKEY_INVITE_TOKENS") or {}
        if set(invite_tokens) != set(ACCOUNT_NAMES):
            raise RuntimeError("운영 환경에는 Account A/B 각각의 PASSKEY_INVITE_TOKENS가 필요합니다.")
        if not config.get("DATABASE_PATH"):
            raise RuntimeError("운영 환경에는 영속 저장소를 가리키는 DATABASE_PATH가 필요합니다.")

    if not config.get("DATABASE_PATH"):
        config["DATABASE_PATH"] = str(BASE_DIR / "instance" / "passkeys.sqlite3")

    if not secret_key:
        config["SECRET_KEY"] = secrets.token_hex(32)

    if not rp_id:
        config["WEBAUTHN_RP_ID"] = "localhost"

    if not origin:
        config["WEBAUTHN_ORIGIN"] = "http://localhost:5000"

    parsed = urlparse(config["WEBAUTHN_ORIGIN"])
    if (
        parsed.scheme not in ("https", "http")
        or not parsed.hostname
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise RuntimeError("WEBAUTHN_ORIGIN은 경로가 없는 유효한 origin URL이어야 합니다.")

    hostname = parsed.hostname.lower()
    rp_id = config["WEBAUTHN_RP_ID"].lower()
    if hostname != rp_id and not hostname.endswith("." + rp_id):
        raise RuntimeError("WEBAUTHN_RP_ID는 origin 호스트와 일치하거나 상위 도메인이어야 합니다.")

    if environment == "production" and parsed.scheme != "https":
        raise RuntimeError("운영 환경의 WebAuthn origin은 HTTPS여야 합니다.")


def get_db():
    if "db" not in g:
        connection = sqlite3.connect(
            current_app.config["DATABASE_PATH"],
            timeout=10,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        g.db = connection
    return g.db


def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db(app):
    database_path = Path(app.config["DATABASE_PATH"])
    database_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(database_path, timeout=10)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                user_handle TEXT NOT NULL UNIQUE,
                invite_used_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS passkeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_id TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                public_key TEXT NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                registered_at TEXT NOT NULL,
                last_used_at TEXT,
                FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_passkeys_username
                ON passkeys(username);

            CREATE TABLE IF NOT EXISTS auth_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attempt_key TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_auth_attempts_key_time
                ON auth_attempts(attempt_key, created_at);

            CREATE TABLE IF NOT EXISTS webauthn_challenges (
                challenge_hash TEXT PRIMARY KEY,
                ceremony TEXT NOT NULL,
                challenge TEXT NOT NULL,
                username TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                consumed_at REAL
            );

            CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_created
                ON webauthn_challenges(created_at);
            """
        )
        connection.commit()
    finally:
        connection.close()


def recent_authentication():
    authenticated_at = session.get("authenticated_at")
    if not isinstance(authenticated_at, (int, float)):
        return False
    return (time.time() - authenticated_at) <= RECENT_AUTH_SECONDS


def request_is_same_origin():
    origin = request.headers.get("Origin")
    return origin == current_app.config["WEBAUTHN_ORIGIN"]


def allow_attempt(username: str, action: str, limit: int = RATE_LIMIT_MAX_ATTEMPTS):
    remote_address = request.remote_addr or "unknown"
    attempt_key = hashlib.sha256(
        f"{action}:{username}:{remote_address}".encode("utf-8")
    ).hexdigest()
    current_time = time.time()
    db = get_db()

    db.execute(
        "DELETE FROM auth_attempts WHERE created_at < ?",
        (current_time - 86400,),
    )
    count = db.execute(
        """
        SELECT COUNT(*) AS total
        FROM auth_attempts
        WHERE attempt_key = ? AND created_at >= ?
        """,
        (attempt_key, current_time - RATE_LIMIT_WINDOW_SECONDS),
    ).fetchone()["total"]

    if count >= limit:
        db.commit()
        return False

    db.execute(
        "INSERT INTO auth_attempts (attempt_key, created_at) VALUES (?, ?)",
        (attempt_key, current_time),
    )
    db.commit()
    return True


def issue_webauthn_challenge(db, ceremony: str, username: str, challenge: bytes, payload: dict):
    encoded_challenge = b64e(challenge)
    challenge_hash = hashlib.sha256(challenge).hexdigest()
    current_time = time.time()

    db.execute(
        "DELETE FROM webauthn_challenges WHERE created_at < ?",
        (current_time - 86400,),
    )
    db.execute(
        """
        INSERT INTO webauthn_challenges
            (challenge_hash, ceremony, challenge, username, payload_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            challenge_hash,
            ceremony,
            encoded_challenge,
            username,
            json.dumps(payload, ensure_ascii=False),
            current_time,
        ),
    )
    db.commit()
    return challenge_hash


def consume_webauthn_challenge(db, challenge_hash: str, ceremony: str):
    if not isinstance(challenge_hash, str) or not challenge_hash:
        return None

    current_time = time.time()
    db.execute("BEGIN IMMEDIATE")
    row = db.execute(
        """
        SELECT challenge, payload_json, created_at
        FROM webauthn_challenges
        WHERE challenge_hash = ? AND ceremony = ? AND consumed_at IS NULL
        """,
        (challenge_hash, ceremony),
    ).fetchone()

    if not row or current_time - row["created_at"] > CHALLENGE_TTL_SECONDS:
        db.rollback()
        return None

    cursor = db.execute(
        """
        UPDATE webauthn_challenges
        SET consumed_at = ?
        WHERE challenge_hash = ? AND consumed_at IS NULL
        """,
        (current_time, challenge_hash),
    )
    if cursor.rowcount != 1:
        db.rollback()
        return None

    db.commit()
    return {
        "challenge": row["challenge"],
        "payload": json.loads(row["payload_json"]),
    }


def json_error(message, status):
    return jsonify({"error": message}), status


def validate_account_name(value):
    return isinstance(value, str) and value in ACCOUNT_NAMES


def create_app(test_config=None):
    app = Flask(__name__)

    app.config.update(
        APP_ENV=os.environ.get("APP_ENV", "development").lower(),
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY"),
        WEBAUTHN_RP_ID=os.environ.get("WEBAUTHN_RP_ID"),
        WEBAUTHN_ORIGIN=os.environ.get("WEBAUTHN_ORIGIN"),
        DATABASE_PATH=os.environ.get("DATABASE_PATH"),
        PASSKEY_INVITE_TOKENS=_invite_tokens_from_env(),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("APP_ENV", "development").lower() == "production",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_CONTENT_LENGTH=256 * 1024,
    )

    if test_config:
        app.config.update(test_config)

    _validate_runtime_config(app.config)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = app.config["APP_ENV"] == "production"

    init_db(app)
    app.teardown_appcontext(close_db)

    @app.context_processor
    def inject_security_nonce():
        return {"csp_nonce": getattr(g, "csp_nonce", "")}

    @app.before_request
    def prepare_request():
        g.csp_nonce = secrets.token_urlsafe(18)

        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.path.startswith("/api/"):
            if not request_is_same_origin():
                return json_error("요청 origin을 확인할 수 없습니다.", 403)

    @app.after_request
    def apply_security_headers(response):
        nonce = getattr(g, "csp_nonce", "")
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            f"style-src 'self' 'nonce-{nonce}'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

        if app.config["APP_ENV"] == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        if request.path == "/private" or request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"

        return response

    @app.get("/")
    def index():
        return render_template("index.html")

    # -----------------------------------------------------
    # Passkey registration
    # -----------------------------------------------------

    @app.post("/api/passkey/register/options")
    def registration_options():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return json_error("올바른 JSON 요청이 필요합니다.", 400)

        username = body.get("username")
        display_name = body.get("display_name", "")
        passkey_name = body.get("passkey_name", "")
        invite_token = body.get("invite_token", "")

        if not validate_account_name(username):
            return json_error("사용할 수 없는 계정입니다.", 400)

        if not isinstance(display_name, str) or len(display_name.strip()) > 60:
            return json_error("표시 이름은 60자 이내로 입력하세요.", 400)

        if not isinstance(passkey_name, str):
            return json_error("패스키 이름을 확인하세요.", 400)
        passkey_name = passkey_name.strip()
        if not passkey_name or len(passkey_name) > 40:
            return json_error("패스키 이름은 1~40자로 입력하세요.", 400)

        if not allow_attempt(username, "registration", limit=5):
            return json_error("등록 요청이 너무 많습니다. 잠시 후 다시 시도하세요.", 429)

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        passkey_count = 0
        if user:
            passkey_count = db.execute(
                "SELECT COUNT(*) AS total FROM passkeys WHERE username = ?",
                (username,),
            ).fetchone()["total"]

        if passkey_count > 0:
            if session.get("authenticated_user") != username or not recent_authentication():
                return json_error("기존 Passkey로 로그인한 뒤 최근 기기 인증을 다시 완료해야 합니다.", 403)
            mode = "add"
            user_handle = user["user_handle"]
        else:
            if user and user["invite_used_at"]:
                return json_error("이 계정의 최초 등록 코드는 이미 사용되었습니다.", 409)

            configured_token = app.config["PASSKEY_INVITE_TOKENS"].get(username)
            if not configured_token:
                return json_error("이 계정의 최초 등록은 현재 비활성화되어 있습니다.", 503)

            if not isinstance(invite_token, str) or not secrets.compare_digest(
                invite_token,
                configured_token,
            ):
                return json_error("초대 코드가 올바르지 않습니다.", 403)

            mode = "bootstrap"
            user_handle = user["user_handle"] if user else b64e(secrets.token_bytes(32))

        registration_challenge = secrets.token_bytes(32)
        options = generate_registration_options(
            rp_id=app.config["WEBAUTHN_RP_ID"],
            rp_name="Ming Personal Profile",
            user_id=b64d(user_handle),
            user_name=username,
            user_display_name=(display_name.strip() or username),
            challenge=registration_challenge,
            timeout=60000,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=b64d(row["credential_id"]))
                for row in db.execute(
                    "SELECT credential_id FROM passkeys WHERE username = ?",
                    (username,),
                ).fetchall()
            ],
        )

        challenge_hash = issue_webauthn_challenge(
            db,
            "registration",
            username,
            options.challenge,
            {
                "username": username,
                "display_name": display_name.strip() or username,
                "passkey_name": passkey_name,
                "user_handle": user_handle,
                "mode": mode,
            },
        )
        session["registration"] = {"challenge_hash": challenge_hash}

        return jsonify(json.loads(options_to_json(options)))

    @app.post("/api/passkey/register/verify")
    def registration_verify():
        pending_session = session.pop("registration", None)
        if not pending_session:
            return json_error("진행 중인 등록 요청이 없습니다. 새 요청을 시작하세요.", 400)

        challenge_state = consume_webauthn_challenge(
            get_db(),
            pending_session.get("challenge_hash"),
            "registration",
        )
        if not challenge_state:
            return json_error("등록 challenge가 만료되었거나 이미 사용되었습니다.", 400)

        pending = challenge_state["payload"]
        credential = request.get_json(silent=True)
        if not isinstance(credential, dict):
            return json_error("등록 응답 형식이 올바르지 않습니다.", 400)

        username = pending["username"]
        if pending["mode"] == "add":
            if session.get("authenticated_user") != username or not recent_authentication():
                return json_error("추가 등록을 위해 기기 인증을 다시 완료해야 합니다.", 403)

        try:
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=b64d(challenge_state["challenge"]),
                expected_rp_id=app.config["WEBAUTHN_RP_ID"],
                expected_origin=app.config["WEBAUTHN_ORIGIN"],
                require_user_verification=True,
            )
        except Exception as exc:
            app.logger.info(
                "Passkey registration verification failed for %s (%s)",
                username,
                type(exc).__name__,
            )
            return json_error("Passkey 등록 검증에 실패했습니다. 새 요청으로 다시 시도하세요.", 400)

        credential_id = b64e(verification.credential_id)
        public_key = b64e(verification.credential_public_key)
        db = get_db()

        try:
            if pending["mode"] == "bootstrap":
                existing = db.execute(
                    "SELECT * FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
                if existing:
                    existing_count = db.execute(
                        "SELECT COUNT(*) AS total FROM passkeys WHERE username = ?",
                        (username,),
                    ).fetchone()["total"]
                    if existing["invite_used_at"] or existing_count > 0:
                        return json_error("이 계정은 이미 초기 등록을 완료했습니다.", 409)

                    db.execute(
                        """
                        UPDATE users
                        SET display_name = ?, invite_used_at = ?
                        WHERE username = ?
                        """,
                        (pending["display_name"], now_iso(), username),
                    )
                else:
                    db.execute(
                        """
                        INSERT INTO users
                            (username, display_name, user_handle, invite_used_at, created_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            username,
                            pending["display_name"],
                            pending["user_handle"],
                            now_iso(),
                            now_iso(),
                        ),
                    )
            else:
                existing = db.execute(
                    "SELECT username FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
                if not existing:
                    return json_error("등록 계정을 찾을 수 없습니다.", 404)

            db.execute(
                """
                INSERT INTO passkeys
                    (credential_id, username, public_key, sign_count, name, registered_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    credential_id,
                    username,
                    public_key,
                    verification.sign_count,
                    pending["passkey_name"],
                    now_iso(),
                ),
            )
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            return json_error("이미 등록된 Passkey이거나 계정 등록 상태가 변경되었습니다.", 409)
        except sqlite3.Error:
            db.rollback()
            app.logger.exception("Database error while saving a Passkey for %s", username)
            return json_error("Passkey 정보를 저장하지 못했습니다.", 500)

        if pending["mode"] == "bootstrap":
            session.clear()
            session.permanent = True
            session["authenticated_user"] = username
            session["authenticated_at"] = time.time()
        else:
            session["authenticated_at"] = time.time()

        return jsonify({
            "ok": True,
            "message": "Passkey 등록이 완료되었습니다.",
        })

    # -----------------------------------------------------
    # Passkey authentication
    # -----------------------------------------------------

    @app.post("/api/passkey/login/options")
    def authentication_options():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return json_error("올바른 JSON 요청이 필요합니다.", 400)

        username = body.get("username")
        if not validate_account_name(username):
            return json_error("계정 또는 등록된 Passkey를 확인할 수 없습니다.", 401)

        if not allow_attempt(username, "login"):
            return json_error("인증 요청이 너무 많습니다. 잠시 후 다시 시도하세요.", 429)

        db = get_db()
        user = db.execute(
            "SELECT username FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not user:
            return json_error("계정 또는 등록된 Passkey를 확인할 수 없습니다.", 401)

        passkeys = db.execute(
            "SELECT credential_id FROM passkeys WHERE username = ?",
            (username,),
        ).fetchall()
        if not passkeys:
            return json_error("계정 또는 등록된 Passkey를 확인할 수 없습니다.", 401)

        authentication_challenge = secrets.token_bytes(32)
        options = generate_authentication_options(
            rp_id=app.config["WEBAUTHN_RP_ID"],
            challenge=authentication_challenge,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=b64d(row["credential_id"]))
                for row in passkeys
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
            timeout=60000,
        )

        challenge_hash = issue_webauthn_challenge(
            db,
            "authentication",
            username,
            options.challenge,
            {"username": username},
        )
        session["authentication"] = {"challenge_hash": challenge_hash}

        return jsonify(json.loads(options_to_json(options)))

    @app.post("/api/passkey/login/verify")
    def authentication_verify():
        pending_session = session.pop("authentication", None)
        if not pending_session:
            return json_error("진행 중인 로그인 요청이 없습니다. 다시 시도하세요.", 400)

        challenge_state = consume_webauthn_challenge(
            get_db(),
            pending_session.get("challenge_hash"),
            "authentication",
        )
        if not challenge_state:
            return json_error("로그인 challenge가 만료되었거나 이미 사용되었습니다.", 400)

        pending = challenge_state["payload"]
        credential = request.get_json(silent=True)
        if not isinstance(credential, dict):
            return json_error("인증 응답 형식이 올바르지 않습니다.", 400)

        credential_id = credential.get("id")
        if not isinstance(credential_id, str) or not credential_id:
            return json_error("인증 응답 형식이 올바르지 않습니다.", 400)

        username = pending["username"]
        if not allow_attempt(username, "login-verify"):
            return json_error("인증 요청이 너무 많습니다. 잠시 후 다시 시도하세요.", 429)

        db = get_db()
        stored = db.execute(
            """
            SELECT id, credential_id, public_key, sign_count
            FROM passkeys
            WHERE username = ? AND credential_id = ?
            """,
            (username, credential_id),
        ).fetchone()

        if not stored:
            return json_error("계정 또는 등록된 Passkey를 확인할 수 없습니다.", 401)

        try:
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=b64d(challenge_state["challenge"]),
                expected_rp_id=app.config["WEBAUTHN_RP_ID"],
                expected_origin=app.config["WEBAUTHN_ORIGIN"],
                credential_public_key=b64d(stored["public_key"]),
                credential_current_sign_count=stored["sign_count"],
                require_user_verification=True,
            )
        except Exception as exc:
            app.logger.info(
                "Passkey authentication failed for %s (%s)",
                username,
                type(exc).__name__,
            )
            return json_error("Passkey 인증에 실패했습니다.", 401)

        db.execute(
            """
            UPDATE passkeys
            SET sign_count = ?, last_used_at = ?
            WHERE id = ?
            """,
            (verification.new_sign_count, now_iso(), stored["id"]),
        )
        db.commit()

        # 새 인증 성공 시 이전 세션 상태를 폐기하고 새 인증 세션을 발급한다.
        session.clear()
        session.permanent = True
        session["authenticated_user"] = username
        session["authenticated_at"] = time.time()

        return jsonify({
            "ok": True,
            "message": "로그인에 성공했습니다.",
            "username": username,
        })

    # -----------------------------------------------------
    # Private area
    # -----------------------------------------------------

    @app.get("/api/private")
    def private_data():
        username = session.get("authenticated_user")
        if username not in PRIVATE_DATA:
            return json_error("인증이 필요합니다.", 401)
        return jsonify(PRIVATE_DATA[username])

    @app.get("/private")
    def private_page():
        username = session.get("authenticated_user")
        if username not in PRIVATE_DATA:
            return redirect(url_for("index"))

        return render_template(
            "private.html",
            username=username,
            data=PRIVATE_DATA[username],
        )

    # -----------------------------------------------------
    # Passkey management
    # -----------------------------------------------------

    @app.get("/api/passkeys")
    def list_passkeys():
        username = session.get("authenticated_user")
        if username not in PRIVATE_DATA:
            return json_error("인증이 필요합니다.", 401)

        rows = get_db().execute(
            """
            SELECT id, name, registered_at, credential_id, public_key
            FROM passkeys
            WHERE username = ?
            ORDER BY registered_at ASC
            """,
            (username,),
        ).fetchall()

        return jsonify({
            "username": username,
            "passkeys": [
                {
                    "id": row["id"],
                    "name": row["name"],
                    "registered_at": row["registered_at"],
                    "credential_id_preview": row["credential_id"][:8] + "...",
                    "public_key_preview": row["public_key"][:16] + "...",
                }
                for row in rows
            ],
            "recent_authentication": recent_authentication(),
        })

    @app.delete("/api/passkeys/<int:passkey_id>")
    def delete_passkey(passkey_id):
        username = session.get("authenticated_user")
        if username not in PRIVATE_DATA:
            return json_error("인증이 필요합니다.", 401)

        if not recent_authentication():
            return json_error("Passkey 삭제 전에 기기 인증을 다시 완료해야 합니다.", 403)

        db = get_db()
        total = db.execute(
            "SELECT COUNT(*) AS total FROM passkeys WHERE username = ?",
            (username,),
        ).fetchone()["total"]

        if total <= 1:
            return json_error("마지막 Passkey는 삭제할 수 없습니다.", 409)

        cursor = db.execute(
            "DELETE FROM passkeys WHERE id = ? AND username = ?",
            (passkey_id, username),
        )
        if cursor.rowcount == 0:
            db.rollback()
            return json_error("해당 Passkey를 찾을 수 없습니다.", 404)

        db.commit()
        return jsonify({"ok": True, "remaining": total - 1})

    @app.post("/api/logout")
    def logout():
        session.clear()
        return jsonify({"ok": True, "message": "로그아웃되었습니다."})

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )
