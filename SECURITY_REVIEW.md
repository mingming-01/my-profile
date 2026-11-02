# Passkey Private Space 보안 점검 및 개선 기록

- 점검 대상: `mingming-01/my-profile`
- 기준 커밋: `d17ecdd506c987cdb82c5bbe83afedffb2c02e50`
- 개선 브랜치: `security/harden-passkey-private-space-20261102`
- 점검일: 2026-11-02
- 범위: Flask API, WebAuthn ceremony, 세션, Passkey 관리 UI, 데이터 저장, 배포 설정

## 1. 점검 요약

기존 구현은 WebAuthn challenge를 생성하고 등록·인증 응답을 검증하는 기본 흐름은 갖추고 있었다. 다만 인증서명 검증만으로는 계정 소유권과 전체 애플리케이션 보안이 보장되지 않는다. 등록 권한, 세션 비밀키, 사용자 입력 렌더링, 데이터 저장 및 배포 설정을 함께 확인해야 했다.

| ID | 심각도 | 발견 사항 | 개선 방향 |
|---|---|---|---|
| SEC-01 | 높음 | 로그인하지 않은 사용자가 Account A/B에 Passkey를 등록할 수 있음 | 계정별 1회용 초대 코드와 소유권 확인 |
| SEC-02 | 높음 | 운영 환경에서 고정된 개발용 SECRET_KEY로 대체될 수 있음 | 운영 환경 Secret Key 필수화 및 시작 시 검증 |
| SEC-03 | 높음 | Passkey 이름을 `innerHTML`에 삽입해 저장형 XSS 가능 | DOM 요소 생성과 `textContent` 사용 |
| SEC-04 | 중간 | challenge 만료 시간이 서버에서 검증되지 않음 | 서버 발급 시각을 저장하고 180초 후 만료 |
| SEC-05 | 중간 | JSON 파일 직접 쓰기로 동시성·손상·배포 저장소 문제가 있음 | SQLite 트랜잭션 및 영속 저장 경로 사용 |
| SEC-06 | 중간 | 상태 변경 API에 Origin 확인이 없음 | 설정된 WebAuthn Origin과 요청 Origin 비교 |
| SEC-07 | 중간 | 로그인·등록 시도 제한과 보안 헤더가 부족함 | 계정/IP 기반 기본 제한, CSP 및 보안 헤더 |
| SEC-08 | 중간 | 세션 만료·인증 상태 초기화·Passkey 삭제 보호가 부족함 | 세션 초기화, 제한된 세션 수명, 재인증, 마지막 Passkey 삭제 방지 |
| SEC-09 | 낮음 | 보안 회귀 테스트가 저장소에 없음 | unittest 테스트 및 GitHub Actions 추가 |

## 2. 주요 위험 분석

### SEC-01. 타인의 계정에 Passkey 등록 가능

기존 `POST /api/passkey/register/options`는 요청 본문에서 Account A 또는 Account B를 선택하는 방식이었으며, 해당 계정의 소유권을 확인하는 절차가 없었다.

따라서 공개 페이지에 접근할 수 있는 사용자가 다른 사람의 Passkey를 테스트 계정에 등록할 수 있었다. 이후 그 계정으로 로그인하면 해당 계정의 Private Space에 접근할 수 있으므로 인증 신뢰성을 훼손하는 문제다.

**개선 사항**
- 최초 등록은 계정별 1회용 비밀 초대 코드를 요구한다.
- 초대 코드는 환경변수에만 저장하고 저장소에는 기록하지 않는다.
- 최초 등록이 성공하면 DB에 사용 여부를 기록해 재사용을 거부한다.
- 기존 Passkey가 있는 계정은 해당 계정으로 로그인한 뒤 최근 기기 인증을 다시 완료해야 추가 등록할 수 있다.
- 등록 검증 과정에서도 계정 상태와 재인증 상태를 다시 확인한다.

### SEC-02. 알려진 개발용 Secret Key fallback

기존 코드에는 환경변수 `FLASK_SECRET_KEY`가 없는 경우 고정된 개발용 문자열을 사용하는 fallback이 있었다.

운영 서버에서 해당 환경변수가 빠지면 공격자가 알려진 키로 Flask 세션 서명을 위조할 가능성이 있다. 세션에 `authenticated_user`가 저장되는 구조이므로 인증 우회로 이어질 수 있다.

**개선 사항**
- `APP_ENV=production`이면 32자 이상의 `FLASK_SECRET_KEY`를 필수로 요구한다.
- 운영 환경에서 필수값이 빠지면 애플리케이션 시작 단계에서 오류를 발생시킨다.
- 로컬 개발 환경에서는 실행 시 임시 키를 생성할 수 있지만, 서버를 재시작하면 기존 로컬 세션은 만료된다.

### SEC-03. Passkey 이름을 통한 저장형 XSS

기존 Private Space는 Passkey 관리 목록에서 사용자 입력인 `key.name`을 템플릿 문자열에 삽입한 뒤 `innerHTML`로 화면에 렌더링했다.

**개선 사항**
- 동적으로 표시하는 값은 DOM 요소의 `textContent`로 출력한다.
- 기존 `innerHTML` 기반 목록 렌더링을 제거한다.
- 인라인 이벤트 핸들러를 제거하고 `addEventListener`를 사용한다.
- CSP nonce 기반 스크립트·스타일 정책을 적용한다.

### SEC-04. Challenge 만료와 재사용

기존 구현은 WebAuthn 옵션에 60초 timeout을 전달했지만 서버가 자체적으로 요청 발급 시각을 검사하지는 않았다.

**개선 사항**
- challenge 값과 발급 시각, 계정, ceremony 유형을 SQLite `webauthn_challenges` 테이블에 저장한다.
- 브라우저 세션에는 challenge 자체가 아니라 challenge hash만 보관한다.
- 검증 시 SQLite 트랜잭션으로 challenge를 원자적으로 소비한다.
- 180초가 지난 challenge는 거부한다.
- 이전에 서명된 세션 쿠키를 다시 제출해도 이미 소비된 challenge는 재사용할 수 없다.
- 인증·등록 실패 시 내부 예외 상세를 브라우저에 반환하지 않는다.

### SEC-05. JSON 파일 저장 방식

기존 코드는 `auth.json`에 데이터를 직접 덮어쓰는 방식이었다. 동시 요청이 발생하거나 파일이 손상되면 저장 데이터가 유실될 수 있었고, 배포 플랫폼의 로컬 파일시스템이 영속 저장을 보장하는지도 확인되지 않았다.

**개선 사항**
- SQLite 테이블로 사용자와 Passkey를 분리했다.
- 외래키, 트랜잭션, busy timeout, WAL 모드를 사용한다.
- DB 경로를 `DATABASE_PATH` 환경변수로 설정한다.
- Render에서는 영속 디스크를 연결한 경우에만 해당 마운트 경로를 DB 경로로 지정한다.

기존 `data/auth.json`의 자격 증명은 등록 계정 소유권을 검증할 수 없으므로 자동 이관하지 않는다. 보안 개선 후에는 초대 코드로 각 계정의 Passkey를 다시 등록해야 한다. 기존 파일은 백업·검토 전까지 직접 삭제하지 않는다.

## 3. 현재 적용한 보안 통제

### 인증 및 계정 등록
- 최초 등록 시 계정별 초대 코드 검증
- 초대 코드 1회 사용 처리
- Passkey 등록 시 사용자 검증(User Verification) 요구
- 기존 등록 자격 증명과 중복 등록 확인
- 로그인 시 사용자별 허용 자격 증명만 제공
- 로그인 성공 후 기존 세션을 비우고 새 인증 세션 생성
- Passkey 추가·삭제 시 최근 5분 내 재인증 확인
- 마지막 Passkey 삭제 방지

### 세션과 요청 보호
- 운영 환경 Secret Key 필수
- HttpOnly, SameSite=Lax, 운영 환경 Secure cookie
- 30분 세션 수명
- 상태 변경 API의 Origin 확인
- 인증·Private API의 no-store 응답
- 등록·로그인 시도 제한

### 브라우저 보안
- CSP nonce 기반 스크립트·스타일 허용
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- HTTPS 운영 환경 HSTS

### 저장
SQLite에 저장하는 정보:
- 계정 식별자와 WebAuthn user handle
- Credential ID
- Credential Public Key
- Sign Count
- Passkey 이름과 등록·최근 사용 시각

Passkey의 개인키는 인증기기에서 관리하며 서버 DB에 저장하지 않는다.

## 4. 필수 환경변수

운영 배포 전 다음 값을 Render 환경변수에 설정해야 한다.

| 변수 | 설명 | 예시 또는 생성 방식 |
|---|---|---|
| `APP_ENV` | 실행 환경 | `production` |
| `FLASK_SECRET_KEY` | Flask 세션 서명 키 | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `WEBAUTHN_RP_ID` | 실제 도메인만 입력 | `my-profile-ohhl.onrender.com` |
| `WEBAUTHN_ORIGIN` | 브라우저에서 접속하는 정확한 HTTPS Origin | `https://my-profile-ohhl.onrender.com` |
| `PASSKEY_INVITE_TOKENS` | 최초 등록 코드 JSON | 계정별 `secrets.token_urlsafe(32)` 결과 사용 |
| `DATABASE_PATH` | SQLite 저장 경로 | 영속 디스크 연결 시 `/var/data/passkeys.sqlite3` |

초대 코드 생성 예시:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

계정별로 서로 다른 코드를 생성하고 Render 환경변수 `PASSKEY_INVITE_TOKENS`에 JSON 객체로 설정한다.

```json
{
  "account-a": "계정 A 전용으로 생성한 32자 이상의 임의 문자열",
  "account-b": "계정 B 전용으로 생성한 다른 임의 문자열"
}
```

위 예시의 설명 문구를 실제 생성한 난수 값으로 교체한다. 실제 코드를 GitHub, README, 화면 코드 또는 공개 이슈에 올리지 않는다.

Render에서 `/var/data`를 영속 디스크 마운트 경로로 사용하는 경우에만 `DATABASE_PATH=/var/data/passkeys.sqlite3`를 설정한다. 영속 디스크가 없다면 재배포·재시작 후 Passkey 등록 데이터가 사라질 수 있다.

## 5. 테스트

로컬에서 환경변수를 준비한 뒤 실행한다.

```bash
python -m unittest discover -s tests -v
```

현재 추가한 테스트는 다음을 확인한다.

- 비로그인 사용자의 Private API 접근 차단
- Origin 누락·불일치 요청 차단
- 최초 등록 초대 코드 요구
- 올바른 코드로 등록 옵션을 생성하되 검증 전 DB 계정은 생성하지 않는지 확인
- 초대 코드 재사용 거부
- 만료 challenge 거부
- 이미 소비한 challenge의 이전 세션 쿠키 재전송 거부
- 계정 존재 여부를 구별하는 로그인 응답 방지
- 마지막 Passkey 삭제 방지
- 보안 헤더 및 no-store 적용
- 로그인 시도 제한
- Private 페이지의 동적 값이 `innerHTML`로 삽입되지 않는지 확인

GitHub Actions의 `.github/workflows/tests.yml`에서도 동일한 테스트를 실행한다.

## 6. 남은 검증 및 제한 사항

이 점검은 저장소의 코드와 테스트를 대상으로 한 정적·단위 수준의 점검이다. 실제 배포 환경에서의 브라우저·기기 조합별 WebAuthn 등록/인증 테스트, Render 환경변수 확인, 영속 디스크 연결 확인, 백업·복구 테스트와 외부 침투 테스트를 대신하지 않는다.

또한 현재 Private Space의 Account A/B 데이터는 접근통제 시연을 위한 고정 샘플 데이터다. 실제 민감정보를 저장하는 개인 비밀번호 보관함이나 범용 비밀 저장소로 소개해서는 안 된다.

WebAuthn 등록은 attestation `none`을 사용하므로 특정 제조사 또는 하드웨어 인증기의 보안 수준을 서버가 증명하는 구조가 아니다. Passkey 플랫폼과 브라우저별 동작을 실제 환경에서 추가 검증해야 한다.

**운영 배포 전 확인이 필요한 항목**
1. Render에 Secret Key, RP ID, Origin, 계정별 초대 코드가 올바르게 설정되어 있는지
2. 데이터베이스 파일이 영속 디스크에 저장되는지
3. 기존 Passkey 등록을 종료하고 초대 코드를 이용해 재등록했는지
4. Chrome/Edge와 실제 기기에서 새 등록, 로그인, 추가 등록, 삭제, 로그아웃을 확인했는지
5. XSS 입력 문자열이 코드로 실행되지 않고 텍스트로만 표시되는지
6. 백업 파일의 생성·복구 절차가 준비되어 있는지

이 프로젝트는 보안 학습 및 포트폴리오 시연용 구현이다. 코드 개선과 자동화 테스트를 추가했더라도 외부 보안 감사나 침투 테스트를 통과한 운영 제품이라고 표현하지 않는다.
