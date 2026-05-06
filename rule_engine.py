"""
Layer 1: 룰 엔진 (Token Validation)

JWT 메타 검증 (RFC 7519, 8725, 9068 기반).
명확한 케이스를 즉시 판정. 회색지대는 LLM 레이어로 넘김.

UBA 행동 분석은 llm_analyzer.py에서 처리.
"""
import time
import re
from collections import defaultdict


# ============================================================
# T-RULES: JWT 토큰 메타 검증 (개별 로그 검사)
# ============================================================

def T001_expired_token(log):
    """
    RFC 7519 §4.1.4: exp 클레임이 현재 시각보다 작으면 거부.
    
    api-server가 검증할 거지만, 검증 누락된 endpoint나
    버그를 통해 통과될 가능성을 사후 탐지.
    """
    exp = log.get("jwt_expires_at")
    if not exp:
        return None
    
    now = int(time.time())
    if exp < now:
        diff = now - exp
        return {
            "rule": "T001",
            "severity": "high",
            "rfc": "RFC 7519 §4.1.4",
            "mitre": "T1550.001",
            "reason": f"만료된 토큰 사용 (만료 후 {diff}초)",
            "evidence": {
                "jwt_expires_at": exp,
                "now": now,
                "expired_seconds_ago": diff
            }
        }
    return None


def T002_long_lived_token(log):
    """
    RFC 9068 §3: Access Token은 짧게 유지 권장 (1시간 이내).
    
    A팀 시스템: exp - iat = 600초 (10분)
    24시간 초과는 위조 토큰 의심 (KMS 키 유출 시 가능).
    """
    iat = log.get("jwt_issued_at")
    exp = log.get("jwt_expires_at")
    if not iat or not exp:
        return None
    
    lifetime = exp - iat
    NORMAL_MAX = 86400  # 24시간 (보수적 임계값)
    
    if lifetime > NORMAL_MAX:
        return {
            "rule": "T002",
            "severity": "high",
            "rfc": "RFC 9068 §3",
            "mitre": "T1550.001",
            "reason": f"비정상 장수명 토큰 ({lifetime//3600}시간, 정상 1시간 이내)",
            "evidence": {
                "lifetime_seconds": lifetime,
                "lifetime_hours": lifetime // 3600
            }
        }
    return None


def T003_future_iat(log):
    """
    RFC 8725 §2.7: iat가 미래 시점이면 토큰 위조 의심.
    
    1분 이상 미래는 비정상 (NTP 시계 차이 고려).
    """
    iat = log.get("jwt_issued_at")
    if not iat:
        return None
    
    now = int(time.time())
    if iat > now + 60:
        return {
            "rule": "T003",
            "severity": "high",
            "rfc": "RFC 8725 §2.7",
            "mitre": "T1550.001",
            "reason": f"미래 시점 발급 토큰 ({iat - now}초 후)",
            "evidence": {
                "jwt_issued_at": iat,
                "now": now,
                "future_seconds": iat - now
            }
        }
    return None


def T004_stale_auth_time(log):
    """
    RFC 9068 §1: auth_time은 실제 인증 시각.
    
    iat - auth_time 차이가 매우 크면 (refresh 사용),
    오래된 인증 정보로 토큰 발급 → 계정 탈취 가능성.
    """
    iat = log.get("jwt_issued_at")
    auth_time = log.get("auth_time")
    if not iat or not auth_time:
        return None
    
    diff = iat - auth_time
    STALE_THRESHOLD = 86400 * 30  # 30일
    
    if diff > STALE_THRESHOLD:
        days = diff // 86400
        return {
            "rule": "T004",
            "severity": "medium",
            "rfc": "RFC 9068 §1",
            "mitre": "T1078",
            "reason": f"오래된 인증 정보로 토큰 발급 ({days}일 전 인증)",
            "evidence": {
                "auth_time_age_days": days,
                "iat_minus_auth_time": diff
            }
        }
    return None


def T005_invalid_audience(log):
    """
    RFC 7519 §4.1.3: aud 클레임이 자신을 식별하지 않으면 거부.
    
    A팀 시스템: aud = ["https://api.zeti.com"]
    다른 aud는 위조 또는 다른 서비스 토큰 재사용 (audience confusion).
    """
    auds = log.get("audiences", [])
    EXPECTED_AUD = "https://api.zeti.com"
    
    if auds and EXPECTED_AUD not in auds:
        return {
            "rule": "T005",
            "severity": "high",
            "rfc": "RFC 7519 §4.1.3",
            "mitre": "T1550.001",
            "reason": f"잘못된 audience: {auds}",
            "evidence": {
                "expected": EXPECTED_AUD,
                "got": auds
            }
        }
    return None


def T006_missing_jti(log):
    """
    RFC 7519 §4.1.7: jti는 토큰 고유 ID, 재생 공격 방지에 필수.
    
    JWT 자체는 있는데 jti 없으면 표준 위반.
    """
    jwt_raw = log.get("jwt_raw", "")
    jwt_id = log.get("jwt_id")
    
    if jwt_raw and not jwt_id:
        return {
            "rule": "T006",
            "severity": "medium",
            "rfc": "RFC 7519 §4.1.7",
            "reason": "JWT에 jti 클레임 누락 (재생 공격 방지 위반)",
            "evidence": {
                "has_jwt": True,
                "has_jti": False
            }
        }
    return None


# ============================================================
# 봇넷/분산 스캔 (전체 데이터셋 검사)
# ============================================================

def C001_botnet_cluster(logs):
    """
    동일 /24 대역에서 5+ IP가 활동 → 봇넷 캠페인 의심.
    
    실제 외부 노출 시 들어오는 봇넷 패턴.
    ZETI 환경에서는 ALB 헬스체크라 거의 안 잡힘 (정상).
    """
    alerts = []
    subnet_24 = defaultdict(set)
    
    for log in logs:
        ip = log.get("ip")
        if not ip:
            continue
        parts = ip.rsplit(".", 1)
        if len(parts) == 2:
            subnet = parts[0] + ".0/24"
            subnet_24[subnet].add(ip)
    
    for subnet, ips in subnet_24.items():
        if len(ips) >= 5:
            alerts.append({
                "rule": "C001",
                "severity": "high",
                "mitre": "T1071",
                "reason": f"동일 /24 대역({subnet})에서 {len(ips)}개 IP 활동 - 봇넷 의심",
                "evidence": {
                    "subnet": subnet,
                    "ip_count": len(ips),
                    "sample_ips": list(ips)[:10]
                }
            })
    
    return alerts


# ============================================================
# 메인: 룰 엔진 통합
# ============================================================

# 개별 로그에 적용할 T-rules
PER_LOG_RULES = [
    T001_expired_token,
    T002_long_lived_token,
    T003_future_iat,
    T004_stale_auth_time,
    T005_invalid_audience,
    T006_missing_jti,
]

# 전체 데이터셋에 적용할 룰
GLOBAL_RULES = [
    C001_botnet_cluster,
]


def analyze_logs(logs):
    """
    Layer 1 룰 엔진 실행.
    
    Args:
        logs: log_fetcher.fetch_recent_logs() 결과
    
    Returns:
        {
            "per_log_alerts": [...],     # 개별 로그 알림
            "global_alerts": [...],      # 전체 패턴 알림
            "passed_to_llm": [...],      # LLM 레이어로 넘길 로그
            "summary": {...}
        }
    """
    per_log_alerts = []
    rule_matched_log_ids = set()
    
    # 개별 로그 검사 (T-rules)
    for i, log in enumerate(logs):
        alerts = []
        for rule_fn in PER_LOG_RULES:
            result = rule_fn(log)
            if result:
                alerts.append(result)
        
        if alerts:
            per_log_alerts.append({
                "log_index": i,
                "log": {
                    "timestamp": log.get("@timestamp"),
                    "ip": log.get("ip"),
                    "method": log.get("method"),
                    "uri": log.get("uri"),
                    "status": log.get("status"),
                    "user_id": log.get("user_id"),
                    "jwt_id": log.get("jwt_id"),
                    "session_id": log.get("session_id")
                },
                "alerts": alerts
            })
            rule_matched_log_ids.add(i)
    
    # 전체 데이터셋 검사 (Cluster 룰)
    global_alerts = []
    for rule_fn in GLOBAL_RULES:
        global_alerts.extend(rule_fn(logs))
    
    # LLM 레이어로 넘길 로그 (룰 매칭 안 된 것)
    passed_to_llm = [
        log for i, log in enumerate(logs)
        if i not in rule_matched_log_ids
    ]
    
    return {
        "per_log_alerts": per_log_alerts,
        "global_alerts": global_alerts,
        "passed_to_llm": passed_to_llm,
        "summary": {
            "total_logs": len(logs),
            "rule_matched": len(per_log_alerts),
            "global_alerts_count": len(global_alerts),
            "passed_to_llm_count": len(passed_to_llm)
        }
    }


# ============================================================
# 테스트
# ============================================================

if __name__ == "__main__":
    import sys
    sys.path.insert(0, '/home/ssm-user/uba-analyzer')
    from log_fetcher import get_es_client, fetch_recent_logs
    
    print("=== Rule Engine 테스트 (실제 데이터) ===\n")
    
    es = get_es_client()
    logs = fetch_recent_logs(es, minutes=120)
    print(f"분석 대상: 최근 2시간 로그 {len(logs)}건\n")
    
    result = analyze_logs(logs)
    
    print("=" * 70)
    print(f"전체 로그: {result['summary']['total_logs']}")
    print(f"룰 매칭 (T-rules): {result['summary']['rule_matched']}")
    print(f"전체 패턴 알림: {result['summary']['global_alerts_count']}")
    print(f"LLM 레이어로 넘길 로그: {result['summary']['passed_to_llm_count']}")
    print("=" * 70)
    
    if result['per_log_alerts']:
        print("\n=== T-rules 매칭 알림 (상위 10개) ===")
        for entry in result['per_log_alerts'][:10]:
            log = entry['log']
            for alert in entry['alerts']:
                sev = alert['severity'].upper()
                print(f"\n  [{sev}] {alert['rule']}: {alert['reason']}")
                print(f"     IP: {log['ip']} | {log['method']} {log['uri'][:50]}")
                if log.get('user_id'):
                    print(f"     user_id: {log['user_id']}, jti: {log['jwt_id'][:12] if log['jwt_id'] else 'N/A'}...")
                if alert.get('rfc'):
                    print(f"     {alert['rfc']}")
                if alert.get('mitre'):
                    print(f"     MITRE: {alert['mitre']}")
    else:
        print("\n  (T-rules 매칭 알림 없음 - 정상 트래픽만 있음)")
    
    if result['global_alerts']:
        print("\n=== 전체 패턴 알림 ===")
        for alert in result['global_alerts']:
            print(f"\n  [{alert['severity'].upper()}] {alert['rule']}: {alert['reason']}")
            if alert.get('evidence'):
                for k, v in alert['evidence'].items():
                    if isinstance(v, list) and len(v) > 5:
                        print(f"     {k}: {v[:5]}... ({len(v)}개)")
                    else:
                        print(f"     {k}: {v}")
    else:
        print("\n  (전체 패턴 알림 없음)")
