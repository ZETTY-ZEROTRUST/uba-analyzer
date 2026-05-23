"""
JWT 파생 필드 계산 (v12 — base64 디코드 제거).

JWT 분해는 Filebeat script processor 가 ingestion 단계에서 끝낸다 (Phase 0.5).
ES filebeat-* doc 는 jwt 를 11+ 클레임 object 로 이미 갖고 있으므로
이 모듈은 더 이상 토큰 문자열을 디코드하지 않는다.

남은 책임: jwt.iat / jwt.exp 정수 클레임 → 토큰 수명 파생 필드.
"""


def derive_token_fields(iat, exp, current_time):
    """jwt 정수 클레임 → 토큰 수명 파생 필드.

    Args:
        iat: jwt.iat (발급 시각, epoch seconds). None 가능.
        exp: jwt.exp (만료 시각, epoch seconds). None 가능.
        current_time: 평가 기준 시각 (epoch seconds).
                      ★ 과거 로그 분석이므로 wall-clock now 가 아니라
                      해당 로그의 서버 수신 시각(@timestamp)을 넘긴다.

    Returns:
        dict: token_age_seconds / token_lifecycle / token_ttl_seconds / token_status.
              입력 클레임이 없으면 해당 키는 생략.
    """
    fields = {}

    if iat is not None:
        age = current_time - iat
        fields["token_age_seconds"] = age
        if age < 60:
            fields["token_lifecycle"] = "fresh"
        elif age < 3600:
            fields["token_lifecycle"] = "active"
        elif age < 86400:
            fields["token_lifecycle"] = "aging"
        else:
            fields["token_lifecycle"] = "stale"

    if exp is not None:
        ttl = exp - current_time
        fields["token_ttl_seconds"] = ttl
        if ttl < 0:
            fields["token_status"] = "expired"
        elif ttl < 60:
            fields["token_status"] = "expiring_soon"
        else:
            fields["token_status"] = "valid"

    return fields


# === 테스트 ===
if __name__ == "__main__":
    now = 1778056393

    print("=== 정상 토큰 (발급 직후) ===")
    print(derive_token_fields(iat=now - 30, exp=now + 14370, current_time=now))

    print("\n=== 만료된 토큰 ===")
    print(derive_token_fields(iat=now - 20000, exp=now - 5600, current_time=now))

    print("\n=== 클레임 없음 ===")
    print(derive_token_fields(iat=None, exp=None, current_time=now))
