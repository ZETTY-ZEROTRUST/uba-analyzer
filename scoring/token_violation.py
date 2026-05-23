"""
token_violation.py — Phase 2: 토큰규격위반 팩터 (결정론, cap 80)

JWT 메타 표준 검증 (RFC 7519/8725/9068). 구 rule_engine.py 의 T-rule 을 흡수했다.

v12 위치:
  - token_violation 은 데모 시나리오가 없는 "상시 룰 레이어". S2/S4/S6 는 유효
    서명 토큰을 쓰므로 매트릭스상 0점이지만, 운영에서 변조/만료 토큰을 잡는
    1차 방어선으로 유지된다.
  - 흡수 내역: T001~T006 보존, T007(비정상 TTL) 추가, C001(/24 봇넷) 제거.
  - 임계값을 backend 정상 TTL 600s 기준으로 맞췄다 (auth-server expiration: 600).
    정상 600s 토큰은 어느 룰도 건드리지 않는다.

설계 의도:
  - 결정론 팩터 — "발생 자체가 비정상". 룰 매칭 = 즉시 점수, baseline 불필요.
  - 한 user-윈도우 안의 여러 토큰 중 가장 높은 위반 점수를 그 윈도우의
    token_violation 으로 삼는다 (max). 위반은 하나만 있어도 비정상이므로 합산하지 않는다.
  - 각 룰은 정규화 로그(log_fetcher.normalize_log 출력) 하나를 받는다.
    'now' 는 wall-clock 이 아니라 그 로그의 서버 수신 시각(receive_epoch).
"""

EXPECTED_AUD = "https://api.zeti.com"   # backend api-server 가 기대하는 aud
TOKEN_VIOLATION_CAP = 80

NORMAL_TTL = 600        # backend 정상 토큰 TTL (auth-server application-prod.yml)
T002_TTL_THRESHOLD = 1800   # 정상 600s 의 3배 — 1차 의심
T007_TTL_THRESHOLD = 3600   # 정상 600s 의 6배 — 강한 위조 의심


def t001_expired(log):
    """RFC 7519 §4.1.4 — exp < 수신시각 이면 만료 토큰."""
    exp, now = log.get("jwt_expires_at"), log.get("receive_epoch")
    if exp is None or now is None:
        return None
    if exp < now:
        return ("T001", 80, f"만료 토큰 (만료 후 {now - exp}초)")
    return None


def t002_long_lived(log):
    """RFC 9068 §3 — access token 은 단명이어야. 정상 600s 대비 과한 TTL."""
    iat, exp = log.get("jwt_issued_at"), log.get("jwt_expires_at")
    if iat is None or exp is None:
        return None
    life = exp - iat
    if life > T002_TTL_THRESHOLD:
        return ("T002", 70, f"장수명 토큰 (TTL {life}s, 정상 {NORMAL_TTL}s)")
    return None


def t003_future_iat(log):
    """RFC 8725 §2.7 — iat 가 미래(>60s)면 위조 의심."""
    iat, now = log.get("jwt_issued_at"), log.get("receive_epoch")
    if iat is None or now is None:
        return None
    if iat > now + 60:
        return ("T003", 80, f"미래 발급 토큰 ({iat - now}초 후)")
    return None


def t004_stale_auth(log):
    """RFC 9068 §1 — 수신시각 − auth_time > 1일 이면 오래된 인증 정보."""
    at, now = log.get("auth_time"), log.get("receive_epoch")
    if at is None or now is None:
        return None
    if now - at > 86400:
        return ("T004", 30, f"오래된 인증 정보 ({(now - at) // 86400}일 전 인증)")
    return None


def t005_invalid_aud(log):
    """RFC 7519 §4.1.3 — aud 가 api.zeti.com 을 포함 안 하면 audience confusion."""
    auds = log.get("audiences") or []
    if auds and EXPECTED_AUD not in auds:
        return ("T005", 70, f"잘못된 audience: {auds}")
    return None


def t006_missing_jti(log):
    """RFC 7519 §4.1.7 — JWT 클레임이 있는데 jti 없으면 재생 방지 위반."""
    if log.get("user_id") and not log.get("jwt_id"):
        return ("T006", 20, "jti 클레임 누락 (재생 공격 방지 위반)")
    return None


def t007_abnormal_ttl(log):
    """v12 신규 — TTL 이 정상의 6배(>3600s)면 강한 위조 의심."""
    iat, exp = log.get("jwt_issued_at"), log.get("jwt_expires_at")
    if iat is None or exp is None:
        return None
    life = exp - iat
    if life > T007_TTL_THRESHOLD:
        return ("T007", 80, f"비정상 TTL ({life}s, 정상 {NORMAL_TTL}s 의 6배 초과)")
    return None


RULES = [t001_expired, t002_long_lived, t003_future_iat, t004_stale_auth,
         t005_invalid_aud, t006_missing_jti, t007_abnormal_ttl]


def check_log(log):
    """단일 정규화 로그 → 위반 결과 리스트 [(rule, score, reason), ...]."""
    return [r for r in (rule(log) for rule in RULES) if r is not None]


def compute_token_violation(logs):
    """user-윈도우의 로그 리스트 → token_violation 팩터 점수 + 증거.

    Args:
        logs: 그 (user, 윈도우) 의 정규화 로그 리스트.

    Returns:
        {"score": 0~80, "triggered_rules": [...], "violating_samples": [...]}
    """
    triggered = {}    # rule -> 그 룰의 점수
    samples = []
    for log in logs:
        for rule, score, reason in check_log(log):
            triggered[rule] = score
            samples.append({"rule": rule, "score": score, "reason": reason,
                            "jti": log.get("jwt_id"), "uri": log.get("uri")})
    score = min(TOKEN_VIOLATION_CAP, max(triggered.values())) if triggered else 0
    return {
        "score": score,
        "triggered_rules": sorted(triggered.keys()),
        "violating_samples": samples[:10],
    }


# === 테스트 ===
if __name__ == "__main__":
    NOW = 1778646770

    def L(**kw):
        base = {"jwt_issued_at": NOW - 100, "jwt_expires_at": NOW + 500,
                "auth_time": NOW - 100, "receive_epoch": NOW,
                "audiences": ["https://api.zeti.com"],
                "user_id": "140000511", "jwt_id": "jti-x", "uri": "/api/products"}
        base.update(kw)
        return base

    normal = L()                                          # TTL 600, valid
    expired = L(jwt_expires_at=NOW - 100)
    long_ttl = L(jwt_issued_at=NOW - 100, jwt_expires_at=NOW + 7200)  # TTL 7300
    no_jti = L(jwt_id=None)
    bad_aud = L(audiences=["https://evil.example.com"])

    assert check_log(normal) == [], f"정상 토큰 무위반, got {check_log(normal)}"
    assert any(r[0] == "T001" for r in check_log(expired)), "만료 → T001"
    longrules = {r[0] for r in check_log(long_ttl)}
    assert {"T002", "T007"} <= longrules, f"장수명 → T002+T007, got {longrules}"
    assert any(r[0] == "T006" for r in check_log(no_jti)), "jti 없음 → T006"
    assert any(r[0] == "T005" for r in check_log(bad_aud)), "잘못된 aud → T005"

    win = compute_token_violation([normal, normal, expired, long_ttl])
    print(f"혼합 윈도우: score={win['score']} rules={win['triggered_rules']}")
    assert win["score"] == 80, "T001 80 포함 → max 80"

    clean = compute_token_violation([normal] * 5)
    print(f"정상 윈도우: score={clean['score']} rules={clean['triggered_rules']}")
    assert clean["score"] == 0, "정상만 → 0 (v12 데모 0점 전제)"

    print("\n계약 점검 통과 ✅ (정상 토큰=0 / 위반 max 채점)")
