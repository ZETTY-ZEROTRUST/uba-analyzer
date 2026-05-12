"""
ES filebeat-* 인덱스에서 nginx 로그 가져오기

- 최근 N분 윈도우 조회
- 필드 정규화 (문자열 → 적절한 타입)
- JWT 디코딩 통합 (jwt_parser 활용)
"""
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta, UTC
from dotenv import load_dotenv
import urllib3
import sys
import os

# 같은 디렉토리의 jwt_parser 임포트
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jwt_parser import decode_jwt_payload, extract_uba_fields

# .env 로드 (ES_HOST, ES_USER, ES_PASS)
load_dotenv()

urllib3.disable_warnings()


# === ES 설정 (env 기반) ===
ES_HOST = os.environ["ES_HOST"]
ES_USER = os.environ["ES_USER"]
ES_PASS = os.environ["ES_PASS"]
INDEX_PATTERN = "filebeat-*"


def get_es_client():
    """ES 클라이언트 생성 (한 번만)"""
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


def normalize_log(raw):
    """
    Filebeat 원본 로그 → 분석용 정규화 형식
    
    - 문자열 필드를 적절한 타입으로 변환
    - JWT 디코딩 + 필드 추출
    - 메타 필드(ecs, host, agent 등) 제거
    """
    # JWT 디코딩
    jwt_payload = decode_jwt_payload(raw.get("jwt", ""))
    jwt_fields = extract_uba_fields(jwt_payload) if jwt_payload else {}
    
    # 정규화된 로그
    return {
        "@timestamp": raw.get("@timestamp"),
        "nginx_time": raw.get("time"),
        "method": raw.get("method", ""),
        "uri": raw.get("uri", ""),
        "status": safe_int(raw.get("status")),
        "ip": raw.get("ip"),
        "response_time": safe_float(raw.get("response_time")),
        "bytes_sent": safe_int(raw.get("bytes_sent")),
        "jwt_raw": raw.get("jwt", ""),
        
        # JWT에서 추출한 식별 정보 (있으면)
        "user_id": jwt_fields.get("user_id"),
        "jwt_id": jwt_fields.get("jwt_id"),
        "session_id": jwt_fields.get("session_id"),
        "client_id": jwt_fields.get("client_id"),
        "jwt_issued_at": jwt_fields.get("jwt_issued_at"),
        "jwt_expires_at": jwt_fields.get("jwt_expires_at"),
        "auth_time": jwt_fields.get("auth_time"),
        "scopes": jwt_fields.get("scopes", []),
        "audiences": jwt_fields.get("audiences", []),
        "issuer": jwt_fields.get("issuer"),
        
        # JWT 파생 필드 (lifecycle, status)
        "token_lifecycle": jwt_fields.get("token_lifecycle"),
        "token_status": jwt_fields.get("token_status"),
        "token_age_seconds": jwt_fields.get("token_age_seconds"),
        "token_ttl_seconds": jwt_fields.get("token_ttl_seconds"),
    }


def fetch_recent_logs(es=None, minutes=15, limit=10000):
    """
    최근 N분 nginx 로그 가져오기
    
    Args:
        es: ES 클라이언트 (없으면 새로 생성)
        minutes: 조회 윈도우 (분)
        limit: 최대 조회 건수
    
    Returns:
        list of dict: 정규화된 로그
    """
    if es is None:
        es = get_es_client()
    
    now = datetime.now(UTC)
    start_time = now - timedelta(minutes=minutes)
    
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": start_time.isoformat(),
                    "lte": now.isoformat()
                }
            }
        },
        "size": limit,
        "sort": [{"@timestamp": "asc"}]
    }
    
    try:
        result = es.search(index=INDEX_PATTERN, body=query)
        raw_logs = [hit["_source"] for hit in result["hits"]["hits"]]
        return [normalize_log(log) for log in raw_logs]
    except Exception as e:
        print(f"  [ERROR] ES 조회 실패: {e}")
        return []


def fetch_logs_for_user(es, user_id, minutes=60):
    """특정 user_id의 최근 N분 로그"""
    if es is None:
        es = get_es_client()
    
    now = datetime.now(UTC)
    start_time = now - timedelta(minutes=minutes)
    
    # JWT 디코딩 후 user_id 매칭은 클라이언트 측에서
    # (ES에는 user_id 필드가 없음)
    raw_results = []
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": start_time.isoformat(),
                    "lte": now.isoformat()
                }
            }
        },
        "size": 10000,
        "sort": [{"@timestamp": "asc"}]
    }
    
    result = es.search(index=INDEX_PATTERN, body=query)
    all_logs = [normalize_log(hit["_source"]) for hit in result["hits"]["hits"]]
    
    return [log for log in all_logs if log.get("user_id") == user_id]


# === 테스트 ===
if __name__ == "__main__":
    print("=== log_fetcher 테스트 ===\n")
    
    es = get_es_client()
    info = es.info()
    print(f"ES 연결 OK - 버전: {info['version']['number']}")
    
    print("\n=== 최근 15분 로그 ===")
    logs = fetch_recent_logs(es, minutes=15)
    print(f"총 {len(logs)}건\n")
    
    if logs:
        print("=== 최신 5건 (정규화된 형식) ===")
        for log in logs[-5:]:
            print(f"\n  [{log['@timestamp']}]")
            print(f"  {log['method']} {log['uri'][:50]}")
            print(f"  ip={log['ip']}, status={log['status']}, bytes={log['bytes_sent']}")
            if log.get("user_id"):
                print(f"  user_id={log['user_id']}, jwt_id={log['jwt_id']}")
                print(f"  token_status={log['token_status']}, lifecycle={log['token_lifecycle']}")
            elif log.get("jwt_raw"):
                print(f"  jwt(raw): {log['jwt_raw'][:50]}...  (디코딩 실패)")
        
        # JWT 있는 로그 통계
        with_jwt = [log for log in logs if log.get("user_id")]
        print(f"\n=== 통계 ===")
        print(f"  전체: {len(logs)}건")
        print(f"  JWT 디코딩 성공: {len(with_jwt)}건")
        print(f"  유저 수 (unique user_id): {len(set(log['user_id'] for log in with_jwt))}")
        print(f"  IP 수 (unique ip): {len(set(log['ip'] for log in logs if log.get('ip')))}")
    else:
        print("  (로그 없음)")
