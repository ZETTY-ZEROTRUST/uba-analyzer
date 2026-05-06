"""
JWT 페이로드 디코더 (분석용, 서명 검증 없음)
쿠팡 스타일 JWT 구조 지원
"""
import base64
import json
import time


def decode_jwt_payload(auth_header):
    """
    Authorization 헤더에서 JWT 페이로드 추출
    
    Args:
        auth_header: "Bearer eyJhbGc..." 형태의 문자열
    
    Returns:
        dict: 디코딩된 페이로드, 실패 시 빈 dict
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        return {}
    
    try:
        token = auth_header[7:]  # "Bearer " 제거
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        
        # Base64 URL-safe 디코딩
        payload_b64 = parts[1]
        payload_b64 = payload_b64.replace("-", "+").replace("_", "/")
        # 패딩 추가
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        
        decoded = base64.b64decode(payload_b64)
        return json.loads(decoded)
        
    except Exception as e:
        return {"_jwt_error": str(e)}


def extract_uba_fields(payload, current_time=None):
    """
    JWT 페이로드에서 UBA 분석에 필요한 필드 추출 + 파생 필드 계산
    
    Args:
        payload: decode_jwt_payload()의 결과
        current_time: 현재 시각 (epoch seconds), 기본값 now
    
    Returns:
        dict: UBA 표준 필드들
    """
    if not payload or "_jwt_error" in payload:
        return {}
    
    if current_time is None:
        current_time = int(time.time())
    
    fields = {
        # === 핵심 식별자 ===
        "user_id": payload.get("sub"),
        "jwt_id": payload.get("jti"),
        "session_id": payload.get("ext", {}).get("LSID"),
        "client_id": payload.get("client_id"),
        
        # === 시간 정보 (epoch seconds) ===
        "jwt_issued_at": payload.get("iat"),
        "jwt_expires_at": payload.get("exp"),
        "auth_time": payload.get("auth_time"),
        
        # === 인증/권한 ===
        "auth_level": payload.get("acr"),
        "auth_methods": payload.get("amr", []),
        "scopes": payload.get("scp", []),
        "audiences": payload.get("aud", []),
        "issuer": payload.get("iss"),
    }
    
    # === 파생 필드 ===
    iat = fields["jwt_issued_at"]
    exp = fields["jwt_expires_at"]
    
    if iat:
        token_age = current_time - iat
        fields["token_age_seconds"] = token_age
        
        if token_age < 60:
            fields["token_lifecycle"] = "fresh"
        elif token_age < 3600:
            fields["token_lifecycle"] = "active"
        elif token_age < 86400:
            fields["token_lifecycle"] = "aging"
        else:
            fields["token_lifecycle"] = "stale"
    
    if exp:
        token_ttl = exp - current_time
        fields["token_ttl_seconds"] = token_ttl
        
        if token_ttl < 0:
            fields["token_status"] = "expired"
        elif token_ttl < 60:
            fields["token_status"] = "expiring_soon"
        else:
            fields["token_status"] = "valid"
    
    return fields


# === 테스트 ===
if __name__ == "__main__":
    import jwt
    import uuid
    
    # 쿠팡 스타일 JWT 생성
    now = int(time.time())
    test_payload = {
        "acr": "aal1",
        "amr": ["pwd"],
        "aud": ["https://www.coupang.com"],
        "auth_time": now - 100,
        "client_id": "4e2e02c8-7456-4bd4-9c75-5b98f2058382",
        "exp": now + 14400,
        "ext": {
            "LSID": str(uuid.uuid4()),
            "fiat": now,
            "v": 2
        },
        "iat": now,
        "iss": "https://mauth.coupang.com/",
        "jti": str(uuid.uuid4()),
        "nbf": now,
        "scp": ["openid", "core", "pay"],
        "sub": "140727747"
    }
    
    test_token = jwt.encode(test_payload, "test-key", algorithm="HS256")
    auth_header = f"Bearer {test_token}"
    
    print("=== JWT 디코딩 테스트 ===")
    decoded = decode_jwt_payload(auth_header)
    print(f"  sub: {decoded.get('sub')}")
    print(f"  jti: {decoded.get('jti')}")
    print(f"  ext.LSID: {decoded.get('ext', {}).get('LSID')}")
    print(f"  scp: {decoded.get('scp')}")
    
    print("\n=== UBA 필드 추출 + 파생 ===")
    uba = extract_uba_fields(decoded)
    for k, v in uba.items():
        print(f"  {k}: {v}")
    
    print("\n=== 에러 케이스 ===")
    bad = decode_jwt_payload("invalid")
    print(f"  invalid: {bad}")
    
    bad2 = decode_jwt_payload("Bearer not.a.real.jwt")
    print(f"  fake: {bad2}")
    
    print("\n=== 빈 헤더 ===")
    empty = extract_uba_fields(decode_jwt_payload(""))
    print(f"  empty: {empty}")
