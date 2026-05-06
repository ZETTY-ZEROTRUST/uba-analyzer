"""
알림 저장 모듈

rule_engine.analyze_logs()의 결과를 ES uba-alerts-* 인덱스에 저장.
일자별 인덱스 사용 (uba-alerts-2026.05.06).
"""
from datetime import datetime, UTC
from elasticsearch import Elasticsearch, helpers
import urllib3

urllib3.disable_warnings()


# === ES 설정 ===
ES_HOST = "https://10.0.41.10:9200"
ES_USER = "elastic"
ES_PASS = "Qx74mrJEwWv3E++6F-AY"


def get_es_client():
    return Elasticsearch(
        [ES_HOST],
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=False
    )


def get_today_index():
    """일자별 인덱스 이름 (uba-alerts-2026.05.06)"""
    today = datetime.now(UTC).strftime("%Y.%m.%d")
    return f"uba-alerts-{today}"


def build_alert_document(rule_alert, log_info, alert_type="rule_engine", layer=1):
    """
    rule_engine 결과 → ES 저장용 alert document 변환
    
    Args:
        rule_alert: rule_engine이 반환한 alert dict
                    (rule, severity, reason, rfc, mitre, evidence)
        log_info:   원본 로그 정보 (timestamp, ip, method, uri, ...)
        alert_type: 알림 출처 ("rule_engine", "global", "llm")
        layer:      탐지 레이어 (1=룰엔진, 2=LLM)
    
    Returns:
        ES 저장용 dict
    """
    return {
        "@timestamp": datetime.now(UTC).isoformat(),
        
        # 알림 분류
        "alert_type": alert_type,
        "layer": layer,
        "rule": rule_alert.get("rule"),
        "severity": rule_alert.get("severity"),
        
        # 탐지 메타
        "detection": {
            "reason": rule_alert.get("reason"),
            "rfc": rule_alert.get("rfc"),
            "mitre": rule_alert.get("mitre"),
            "cve": rule_alert.get("cve"),
        },
        
        # 원본 로그 정보 (있으면)
        "user_id": log_info.get("user_id") if log_info else None,
        "session_id": log_info.get("session_id") if log_info else None,
        "jwt_id": log_info.get("jwt_id") if log_info else None,
        "ip": log_info.get("ip") if log_info else None,
        "method": log_info.get("method") if log_info else None,
        "uri": log_info.get("uri") if log_info else None,
        "status": log_info.get("status") if log_info else None,
        "log_timestamp": log_info.get("timestamp") if log_info else None,
        
        # 증거
        "evidence": rule_alert.get("evidence", {}),
    }


def save_alerts(rule_engine_result, es=None):
    """
    rule_engine.analyze_logs() 결과를 ES에 저장.
    
    Args:
        rule_engine_result: analyze_logs()의 반환값
                            {per_log_alerts, global_alerts, ...}
        es: ES 클라이언트 (없으면 새로 생성)
    
    Returns:
        {
            "saved": int,    # 저장된 알림 수
            "failed": int,   # 실패한 알림 수
            "index": str     # 사용한 인덱스 이름
        }
    """
    if es is None:
        es = get_es_client()
    
    index = get_today_index()
    documents = []
    
    # 개별 로그 알림 (per_log_alerts)
    for entry in rule_engine_result.get("per_log_alerts", []):
        log_info = entry.get("log", {})
        for alert in entry.get("alerts", []):
            doc = build_alert_document(alert, log_info, "rule_engine", layer=1)
            documents.append({
                "_index": index,
                "_source": doc
            })
    
    # 전체 패턴 알림 (global_alerts)
    for alert in rule_engine_result.get("global_alerts", []):
        # 전체 패턴은 특정 로그에 안 묶임
        doc = build_alert_document(alert, None, "global", layer=1)
        documents.append({
            "_index": index,
            "_source": doc
        })
    
    if not documents:
        return {"saved": 0, "failed": 0, "index": index}
    
    # Bulk 저장
    saved, failed = 0, 0
    try:
        success_count, errors = helpers.bulk(
            es,
            documents,
            raise_on_error=False,
            stats_only=False
        )
        saved = success_count
        es.indices.refresh(index=index)
        failed = len(errors) if isinstance(errors, list) else 0
    except Exception as e:
        print(f"  [ERROR] ES 저장 실패: {e}")
        failed = len(documents)
    
    return {
        "saved": saved,
        "failed": failed,
        "index": index
    }


def query_alerts(es=None, hours=1, severity=None):
    """
    저장된 알림 조회 (검증/디버깅용)
    
    Args:
        es:       ES 클라이언트
        hours:    최근 N시간 알림
        severity: 필터링할 severity (None이면 전체)
    """
    if es is None:
        es = get_es_client()
    
    must_conditions = [
        {"range": {
            "@timestamp": {
                "gte": f"now-{hours}h"
            }
        }}
    ]
    
    if severity:
        must_conditions.append({"term": {"severity": severity}})
    
    query = {
        "query": {"bool": {"must": must_conditions}},
        "size": 100,
        "sort": [{"@timestamp": "desc"}]
    }
    
    try:
        result = es.search(index="uba-alerts-*", body=query)
        return [hit["_source"] for hit in result["hits"]["hits"]]
    except Exception as e:
        print(f"  [ERROR] 조회 실패: {e}")
        return []


# ============================================================
# 테스트
# ============================================================

if __name__ == "__main__":
    import sys
    sys.path.insert(0, '/home/ssm-user/uba-analyzer')
    from log_fetcher import fetch_recent_logs
    from rule_engine import analyze_logs
    
    print("=== alert_saver 테스트 ===\n")
    
    es = get_es_client()
    
    # 1. 로그 수집 + 분석
    print("[1] 로그 수집 + 룰 엔진 분석")
    logs = fetch_recent_logs(es, minutes=120)
    result = analyze_logs(logs)
    print(f"  분석: {result['summary']['total_logs']}건")
    print(f"  알림: {result['summary']['rule_matched']}건")
    print()
    
    # 2. 알림 저장
    print("[2] 알림 저장")
    save_result = save_alerts(result, es)
    print(f"  인덱스: {save_result['index']}")
    print(f"  저장: {save_result['saved']}건")
    print(f"  실패: {save_result['failed']}건")
    print()
    
    # 3. 저장된 알림 조회
    print("[3] 저장된 알림 조회 (최근 1시간)")
    alerts = query_alerts(es, hours=1)
    print(f"  조회: {len(alerts)}건\n")
    
    if alerts:
        print("=== 최근 알림 (상위 3개) ===")
        for alert in alerts[:3]:
            print(f"\n  [{alert.get('severity', '?').upper()}] {alert.get('rule', '?')}")
            print(f"     {alert.get('detection', {}).get('reason', '?')}")
            print(f"     user_id: {alert.get('user_id')}, ip: {alert.get('ip')}")
            print(f"     uri: {alert.get('uri')}")
            print(f"     timestamp: {alert.get('@timestamp')}")
            if alert.get('detection', {}).get('rfc'):
                print(f"     {alert['detection']['rfc']}")


# ============================================================
# LLM 알림 저장 (Layer 2)
# ============================================================

def save_llm_alerts(llm_alerts, es=None):
    """
    llm_analyzer.analyze_with_llm() 결과를 ES에 저장
    
    Args:
        llm_alerts: analyze_with_llm() 반환값 (list of dict)
                    [{"log": {...}, "alerts": [{...}]}]
        es: ES 클라이언트
    
    Returns:
        {"saved": int, "failed": int, "index": str}
    """
    if es is None:
        es = get_es_client()
    
    index = get_today_index()
    documents = []
    
    for entry in llm_alerts:
        log_info = entry.get("log", {})
        for alert in entry.get("alerts", []):
            doc = build_alert_document(alert, log_info, alert_type="llm", layer=2)
            documents.append({
                "_index": index,
                "_source": doc
            })
    
    if not documents:
        return {"saved": 0, "failed": 0, "index": index}
    
    saved, failed = 0, 0
    try:
        success_count, errors = helpers.bulk(
            es, documents,
            raise_on_error=False,
            stats_only=False
        )
        saved = success_count
        failed = len(errors) if isinstance(errors, list) else 0
        # refresh로 즉시 검색 가능하게
        es.indices.refresh(index=index)
    except Exception as e:
        print(f"  [ERROR] LLM 알림 저장 실패: {e}")
        failed = len(documents)
    
    return {
        "saved": saved,
        "failed": failed,
        "index": index
    }
