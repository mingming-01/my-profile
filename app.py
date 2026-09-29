import base64
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
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
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    AuthenticatorAttachment,
)


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
AUTH_FILE = DATA_DIR / "auth.json"

DATA_DIR.mkdir(exist_ok=True)

app = Flask(__name__)

# 실제 배포에서는 환경변수 FLASK_SECRET_KEY를 사용한다.
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "task8-development-secret-change-before-deploy",
)

RP_NAME = "Ming Personal Profile"

# 로컬 개발용.
# 배포할 때 실제 HTTPS 도메인에 맞춰 변경한다.
RP_ID = os.environ.get("WEBAUTHN_RP_ID", "my-profile.test")
ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "https://my-profile.test:5000")


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


def load_data():
    if not AUTH_FILE.exists():
        return {"users": {}}

    try:
        return json.loads(AUTH_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"users": {}}


def save_data(data):
    AUTH_FILE.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64d(value: str) -> bytes:
    return base64url_to_bytes(value)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_user(username):
    data = load_data()
    return data["users"].get(username)


@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------
# Registration
# ---------------------------------------------------------

@app.post("/api/passkey/register/options")
def registration_options():
    body = request.get_json(silent=True) or {}

    username = body.get("username", "").strip()
    display_name = body.get("display_name", "").strip()
    passkey_name = body.get("passkey_name", "").strip()

    if username not in PRIVATE_DATA:
        return jsonify({
            "error": "사용할 수 없는 계정입니다. account-a 또는 account-b를 사용하세요."
        }), 400

    if not passkey_name:
        return jsonify({"error": "패스키 이름을 입력하세요."}), 400

    data = load_data()

    user = data["users"].setdefault(
        username,
        {
            "username": username,
            "display_name": display_name or username,
            "passkeys": [],
        },
    )

    existing_credentials = [
        PublicKeyCredentialDescriptor(
            id=b64d(item["credential_id"])
        )
        for item in user["passkeys"]
    ]

    user_id = secrets.token_bytes(32)

    # 계정에 user_id가 이미 있으면 기존 값을 사용한다.
    if "user_id" in user:
        user_id = b64d(user["user_id"])
    else:
        user["user_id"] = b64e(user_id)

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id,
        user_name=username,
        user_display_name=display_name or username,
        challenge=secrets.token_bytes(32),
        timeout=60000,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=existing_credentials,
    )

    # 등록 ceremony가 끝날 때까지 서버에 challenge 보관
    session["registration"] = {
        "username": username,
        "passkey_name": passkey_name,
        "challenge": b64e(options.challenge),
    }

    return jsonify(json.loads(options_to_json(options)))


@app.post("/api/passkey/register/verify")
def registration_verify():
    pending = session.get("registration")

    if not pending:
        return jsonify({
            "error": "진행 중인 패스키 등록 요청이 없습니다."
        }), 400

    credential = request.get_json(silent=True)

    if not credential:
        return jsonify({"error": "등록 응답이 없습니다."}), 400

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=b64d(pending["challenge"]),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=True,
        )
    except Exception as exc:
        session.pop("registration", None)

        return jsonify({
            "error": "패스키 등록 검증 실패",
            "detail": str(exc),
        }), 400

    data = load_data()
    username = pending["username"]

    user = data["users"].setdefault(
        username,
        {
            "username": username,
            "display_name": username,
            "passkeys": [],
        },
    )

    credential_id = b64e(verification.credential_id)

    # 같은 credential 중복 등록 방지
    if any(
        item["credential_id"] == credential_id
        for item in user["passkeys"]
    ):
        session.pop("registration", None)

        return jsonify({
            "error": "이미 등록된 패스키입니다."
        }), 409

    user["passkeys"].append({
        "credential_id": credential_id,
        "public_key": b64e(verification.credential_public_key),
        "sign_count": verification.sign_count,
        "name": pending["passkey_name"],
        "registered_at": now_iso(),
    })

    save_data(data)

    session.pop("registration", None)

    return jsonify({
        "ok": True,
        "message": "패스키 등록 완료",
        "credential_id": credential_id,
        "public_key": b64e(verification.credential_public_key),
    })


# ---------------------------------------------------------
# Authentication
# ---------------------------------------------------------

@app.post("/api/passkey/login/options")
def authentication_options():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "").strip()

    user = get_user(username)

    if not user:
        return jsonify({
            "error": "등록된 계정을 찾을 수 없습니다."
        }), 404

    if not user["passkeys"]:
        return jsonify({
            "error": "등록된 패스키가 없습니다."
        }), 403

    allow_credentials = [
        PublicKeyCredentialDescriptor(
            id=b64d(item["credential_id"])
        )
        for item in user["passkeys"]
    ]

    # 로그인마다 새로운 challenge 생성
    options = generate_authentication_options(
        rp_id=RP_ID,
        challenge=secrets.token_bytes(32),
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000,
    )

    session["authentication"] = {
        "username": username,
        "challenge": b64e(options.challenge),
    }

    return jsonify(json.loads(options_to_json(options)))


@app.post("/api/passkey/login/verify")
def authentication_verify():
    pending = session.get("authentication")

    if not pending:
        return jsonify({
            "error": "진행 중인 로그인 요청이 없습니다."
        }), 400

    credential = request.get_json(silent=True) or {}

    credential_id = credential.get("id")

    if not credential_id:
        return jsonify({"error": "credential id가 없습니다."}), 400

    data = load_data()
    username = pending["username"]
    user = data["users"].get(username)

    if not user:
        return jsonify({"error": "사용자를 찾을 수 없습니다."}), 404

    stored = next(
        (
            item
            for item in user["passkeys"]
            if item["credential_id"] == credential_id
        ),
        None,
    )

    if not stored:
        session.pop("authentication", None)

        return jsonify({
            "error": "이 계정에 등록되지 않은 패스키입니다."
        }), 403

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=b64d(pending["challenge"]),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=b64d(stored["public_key"]),
            credential_current_sign_count=stored["sign_count"],
            require_user_verification=True,
        )
    except Exception as exc:
        # 실패한 challenge는 재사용하지 못하게 폐기
        session.pop("authentication", None)

        return jsonify({
            "error": "패스키 로그인 검증 실패",
            "detail": str(exc),
        }), 401

    stored["sign_count"] = verification.new_sign_count

    save_data(data)

    # challenge 폐기
    session.pop("authentication", None)

    # 로그인 세션
    session["authenticated_user"] = username

    return jsonify({
        "ok": True,
        "message": "로그인 성공",
        "username": username,
    })


# ---------------------------------------------------------
# Private data
# ---------------------------------------------------------

@app.get("/api/private")
def private_data():
    username = session.get("authenticated_user")

    if not username:
        return jsonify({
            "error": "인증이 필요합니다."
        }), 401

    return jsonify(PRIVATE_DATA[username])


@app.get("/private")
def private_page():
    if not session.get("authenticated_user"):
        return redirect(url_for("index"))

    return render_template(
        "private.html",
        username=session["authenticated_user"],
        data=PRIVATE_DATA[session["authenticated_user"]],
    )


# ---------------------------------------------------------
# Passkey management
# ---------------------------------------------------------

@app.get("/api/passkeys")
def list_passkeys():
    username = session.get("authenticated_user")

    if not username:
        return jsonify({
            "error": "인증이 필요합니다."
        }), 401

    user = get_user(username)

    return jsonify({
        "username": username,
        "passkeys": [
            {
                "name": item["name"],
                "registered_at": item["registered_at"],
                "credential_id": item["credential_id"][:8] + "...",
                "public_key": item["public_key"][:16] + "...",
            }
            for item in user["passkeys"]
        ],
    })


@app.delete("/api/passkeys/<credential_id>")
def delete_passkey(credential_id):
    username = session.get("authenticated_user")

    if not username:
        return jsonify({
            "error": "인증이 필요합니다."
        }), 401

    data = load_data()
    user = data["users"].get(username)

    if not user:
        return jsonify({"error": "사용자를 찾을 수 없습니다."}), 404

    before = len(user["passkeys"])

    user["passkeys"] = [
        item
        for item in user["passkeys"]
        if item["credential_id"] != credential_id
    ]

    if len(user["passkeys"]) == before:
        return jsonify({
            "error": "패스키를 찾을 수 없습니다."
        }), 404

    save_data(data)

    return jsonify({
        "ok": True,
        "remaining": len(user["passkeys"]),
    })


# ---------------------------------------------------------
# Logout
# ---------------------------------------------------------

@app.post("/api/logout")
def logout():
    session.pop("authenticated_user", None)

    return jsonify({
        "ok": True,
        "message": "로그아웃 완료",
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )