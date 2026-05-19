"""
ES filebeat-* 인덱스에서 nginx 로그 가져오기 (v12)

- 최근 N분 / 임의 시간 범위 윈도우 조회
- 필드 정규화: Filebeat 가 분해한 jwt object + asn-classify 메타를 평탄화
- ★ v12: JWT 디코드 안 함 (Filebeat script processor 가 ingestion 에서 끝냄).
  raw["jwt"] 는 이미 11+ 클레임 object.
"""
from elasticsearch import Elasticsearch, helpers
from datetime import datetime, timedelta, timezone, UTC
from dotenv import load_dotenv
import urllib3
import sys
import os

# 같은 디렉토리의 jwt_parser 임포트
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jwt_parser import derive_token_fields

# .env 로드 (ES_HOST, ES_USER, ES_PASS)
load_dotenv()

urllib3.disable_warnings()


# === ES 설정 (env 기반) ===
ES_HOST = os.environ["ES_HOST"]
ES_USER = os.environ["ES_USER"]
ES_PASS = os.environ["ES_PASS"]
INDEX_PATTERN = "filebeat-*"


def get_es_client():
    """ES 클라이언트 생성"""
    return Elasticsearch(
        [ES_HOST],
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=False
    )


def safe_int(value, default=0):
    """문자열 → int 안전 변환"""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value, default=0.0):
    """문자열 → float 안전 변환"""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def iso_to_epoch(ts):
    """ES @timestamp ISO 문자열 → epoch seconds (int). 실패 시 None."""
    if not ts:
        return None
    try:
        # "2026-05-13T09:13:13Z" / "...+00:00" 모두 처리
        return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
    except (ValueError, AttributeError):
        return None


def normalize_log(raw):
    """
    Filebeat filebeat-* doc (v12) → 분석용 정규화 레코드.

    raw["jwt"] 는 Filebeat script processor 가 분해한 object (alg/kid/sub/jti/iat/
    exp/auth_time/iss/aud/client_id/scp/acr/amr/ext{LSID,fiat,v}).
    raw 의 client_ip / ip_class / ip_asn 등은 asn-classify pipeline (또는 seed) 산출.
    """
    jwt = raw.get("jwt") or {}
    ext = jwt.get("ext") or {}

    timestamp = raw.get("@timestamp")
    # 토큰 수명 파생은 wall-clock now 가 아니라 서버 수신 시각 기준 (과거 로그 분석)
    receive_epoch = iso_to_epoch(timestamp)
    iat = jwt.get("iat")
    exp = jwt.get("exp")
    derived = derive_token_fields(iat, exp, receive_epoch if receive_epoch else 0)

    return {
        # === 시각 ===
        "timestamp": timestamp,
        "receive_epoch": receive_epoch,        # 서버 수신 시각 — token_replay 윈도우 기준

        # === 요청 ===
        "method": raw.get("method", ""),
        "uri": raw.get("uri", ""),
        "status": safe_int(raw.get("status")),
        "response_time": safe_float(raw.get("response_time")),
        "bytes_sent": safe_int(raw.get("bytes_sent")),
        "user_agent": raw.get("user_agent"),

        # === IP / ASN 분류 (asn-classify or seed) ===
        "client_ip": raw.get("client_ip"),     # 실 클라이언트 (x_forwarded_for 첫 IP)
        "alb_ip": raw.get("ip"),               # nginx 가 본 직접 클라이언트 (ALB)
        "ip_class": raw.get("ip_class"),       # cgnat_kr / cloud / unknown ...
        "ip_asn": raw.get("ip_asn"),
        "ip_org": raw.get("ip_org"),
        "ip_country": raw.get("ip_country"),
        "is_nat_whitelisted": raw.get("is_nat_whitelisted"),

        # === seed provenance (실 트래픽엔 없음 — zeti_seed 메타) ===
        "seed_scenario": (raw.get("zeti_seed") or {}).get("scenario"),
        "baseline_eligible": (raw.get("zeti_seed") or {}).get("baseline_eligible", True),

        # === JWT 클레임 (Filebeat 분해 완료) ===
        "user_id": jwt.get("sub"),
        "jwt_id": jwt.get("jti"),
        "session_id": ext.get("LSID"),
        "client_id": jwt.get("client_id"),
        "alg": jwt.get("alg"),
        "kid": jwt.get("kid"),
        "jwt_issued_at": iat,
        "jwt_expires_at": exp,
        "auth_time": jwt.get("auth_time"),
        "acr": jwt.get("acr"),
        "amr": jwt.get("amr") or [],
        "scopes": jwt.get("scp") or [],
        "audiences": jwt.get("aud") or [],
        "issuer": jwt.get("iss"),

        # === JWT 파생 필드 ===
        "token_lifecycle": derived.get("token_lifecycle"),
        "token_status": derived.get("token_status"),
        "token_age_seconds": derived.get("token_age_seconds"),
        "token_ttl_seconds": derived.get("token_ttl_seconds"),
    }


def fetch_recent_logs(es=None, minutes=15, limit=10000):
    """최근 N분 nginx 로그 → 정규화 레코드 리스트."""
    if es is None:
        es = get_es_client()
    now = datetime.now(UTC)
    return fetch_logs_in_range(es, now - timedelta(minutes=minutes), now, limit)


def fetch_logs_in_range(es, start, end, limit=None):
    """
    임의 [start, end] 구간의 nginx 로그 → 정규화 레코드 리스트.

    seed baseline 은 과거 168h 구간이므로 minutes 윈도우로는 못 잡는다.
    Phase 1 aggregator 는 이 함수로 윈도우를 직접 지정한다.

    helpers.scan 으로 구간 전체를 페이지네이션한다 — 단일 search 의
    max_result_window(10k) 한도 제거. seed 가 10k 를 넘겨도 전량 소비
    (PHASE_1_2 §7 예고 보강). limit: None 이면 전체, 정수면 그 수에서 컷.
    """
    if es is None:
        es = get_es_client()
    query = {"query": {"range": {"@timestamp": {
        "gte": start.isoformat(), "lte": end.isoformat()}}}}
    try:
        logs = []
        for hit in helpers.scan(es, index=INDEX_PATTERN, query=query,
                                preserve_order=False, size=2000):
            logs.append(normalize_log(hit["_source"]))
            if limit is not None and len(logs) >= limit:
                break
        return logs
    except Exception as e:
        print(f"  [ERROR] ES 조회 실패: {e}")
        return []


def fetch_logs_for_user(es, user_id, minutes=60):
    """특정 user_id 의 최근 N분 로그 (클라이언트 측 필터)."""
    logs = fetch_recent_logs(es, minutes=minutes)
    return [log for log in logs if log.get("user_id") == user_id]


# === 테스트 ===
if __name__ == "__main__":
    print("=== log_fetcher 연결 테스트 ===\n")
    es = get_es_client()
    info = es.info()
    print(f"ES 연결 OK - 버전: {info['version']['number']}")

    logs = fetch_recent_logs(es, minutes=60)
    print(f"\n최근 60분 로그: {len(logs)}건")
    if logs:
        with_jwt = [g for g in logs if g.get("user_id")]
        print(f"  JWT 클레임 있는 로그: {len(with_jwt)}건")
        print(f"  unique user_id: {len(set(g['user_id'] for g in with_jwt))}")
        print(f"  unique client_ip: {len(set(g['client_ip'] for g in logs if g.get('client_ip')))}")
        sample = logs[-1]
        print(f"\n  샘플: {sample['method']} {sample['uri'][:40]} "
              f"user={sample['user_id']} ip_class={sample['ip_class']} "
              f"token_status={sample['token_status']}")
