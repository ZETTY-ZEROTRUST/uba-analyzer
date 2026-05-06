"""
Layer 2: LLM 기반 행동 분석

rule_engine에서 통과한 로그 중 의심스러운 사용자만 LLM에 보내 추론.
LLM은 사용자별 행동 패턴을 자연어로 분석하고 알림 생성.

비용 통제:
  - should_check_user() 필터로 의심 사용자만 LLM 호출
  - 정상 사용자는 LLM 안 보냄
  - Claude Haiku 4.5 (저렴한 모델)
"""
import os
import json
import logging
from collections import defaultdict
from anthropic import Anthropic


# === 환경 변수 로드 ===
def load_env():
    """~/uba-analyzer/.env 로드"""
    env_path = os.path.expanduser("~/uba-analyzer/.env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    os.environ[key.strip()] = val.strip()

load_env()


# === LLM 설정 ===
MODEL = "claude-haiku-4-5"
MAX_TOKENS = 1024


logger = logging.getLogger("llm-analyzer")


def get_anthropic_client():
    """Anthropic 클라이언트 생성"""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY 환경 변수 없음")
    return Anthropic(api_key=api_key)


def should_check_user(user_logs):
    """
    LLM에 보낼 가치 있는 사용자만 필터.
    
    비용 통제 핵심: 정상 사용자는 절대 LLM 안 보냄.
    """
    if not user_logs:
        return False
    
    # 1. 활동량 너무 적으면 정상으로 간주 (단, 의심 endpoint 있으면 예외)
    SUSPICIOUS_PATHS = ['/admin/', '/internal/', '/private/', '/secret/', '/system/', '/debug/', '/backup', '/.env', '/.git']
    has_suspicious_path = any(
        any(p in log.get("uri", "") for p in SUSPICIOUS_PATHS)
        for log in user_logs
    )
    
    if has_suspicious_path:
        return True  # admin/internal 등 의심 endpoint 시도 → 무조건 검사
    
    if len(user_logs) < 3:
        return False
    
    # 2. 너무 많으면 무조건 의심
    if len(user_logs) > 200:
        return True
    
    # 3. 4xx/5xx 비율 높으면 의심
    error_count = sum(1 for log in user_logs if log.get("status", 0) >= 400)
    if error_count / len(user_logs) > 0.3:
        return True
    
    # 4. URI 다양성 (정찰 의심)
    unique_uris = set(log.get("uri", "").split("?")[0] for log in user_logs)
    if len(unique_uris) > 15:
        return True
    
    # 5. 같은 endpoint 폭주 (Abuse 패턴)
    if len(unique_uris) == 1 and len(user_logs) >= 20:
        return True
    
    # 6. IDOR 패턴
    import re
    user_id_pattern = re.compile(r"/api/users/(\d+)")
    own_id = user_logs[0].get("user_id")
    accessed_ids = set()
    for log in user_logs:
        match = user_id_pattern.search(log.get("uri", ""))
        if match:
            accessed_ids.add(match.group(1))
    
    if own_id and len(accessed_ids - {own_id}) >= 2:
        return True
    
    return False

def format_logs_for_prompt(user_logs, max_logs=20):
    """LLM 프롬프트용 로그 포맷팅"""
    sample = user_logs[:max_logs]
    lines = []
    for i, log in enumerate(sample, 1):
        ts = log.get("@timestamp", "")[:19]
        method = log.get("method", "?")
        uri = log.get("uri", "?")[:80]
        status = log.get("status", "?")
        ip = log.get("ip", "?")
        lines.append(f"  {i}. [{ts}] {method} {uri} → {status} (IP: {ip})")
    
    note = ""
    if len(user_logs) > max_logs:
        note = f"\n  ... (총 {len(user_logs)}건 중 처음 {max_logs}건만 표시)"
    
    return "\n".join(lines) + note


def analyze_user_with_llm(client, user_id, user_logs):
    """
    한 사용자의 행동을 LLM으로 분석
    
    Args:
        client: Anthropic 클라이언트
        user_id: 사용자 ID (JWT sub)
        user_logs: 해당 사용자의 로그 리스트
    
    Returns:
        dict or None: 알림 dict (이상 시), None (정상 시)
    """
    log_summary = format_logs_for_prompt(user_logs)
    
    prompt = f"""당신은 보안 분석가입니다. 다음 사용자의 5분간 활동을 분석하세요.

사용자 ID: {user_id}
총 요청 수: {len(user_logs)}건

요청 로그:
{log_summary}

다음 보안 위협 패턴을 검토하세요:
1. IDOR (Insecure Direct Object Reference): 다른 사용자의 데이터 조회 시도
2. 정찰 (Reconnaissance): 비정상적으로 많은 endpoint 탐색
3. 권한 상승: 자기 권한 외 endpoint 접근
4. 토큰 재사용/공유 (jti가 여러 IP에서 사용)
5. 비정상적 4xx/5xx 폭증 (스캐닝 의심)
6. 기타 의심스러운 행동 패턴

JSON 형식으로만 응답하세요. 다른 설명 추가하지 마세요.

{{
  "is_anomaly": true 또는 false,
  "severity": "critical" 또는 "high" 또는 "medium" 또는 "low",
  "rule_label": "U-LLM-IDOR" 또는 "U-LLM-RECON" 또는 "U-LLM-PRIV-ESC" 등 짧은 레이블,
  "reason": "한 문장 한국어 설명",
  "evidence": ["증거1", "증거2"],
  "mitre_attack": "T1190" 등 MITRE ATT&CK ID (해당하면)
}}

정상이면 is_anomaly: false. 이 경우 나머지 필드 채울 필요 없음."""
    
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}]
        )
        
        # 응답 파싱
        text = response.content[0].text.strip()
        
        # JSON 추출 (LLM이 ```json ... ``` 블록으로 감싸기도 함)
        if "```" in text:
            # 첫 번째 ``` 블록 추출
            parts = text.split("```")
            for part in parts:
                if "{" in part:
                    text = part.replace("json", "", 1).strip()
                    break
        
        result = json.loads(text)
        
        if result.get("is_anomaly"):
            return {
                "rule": result.get("rule_label", "U-LLM"),
                "severity": result.get("severity", "medium"),
                "mitre": result.get("mitre_attack"),
                "reason": result.get("reason", ""),
                "evidence": {
                    "user_id": user_id,
                    "log_count": len(user_logs),
                    "llm_evidence": result.get("evidence", []),
                    "model": MODEL
                }
            }
        return None
        
    except json.JSONDecodeError as e:
        logger.warning(f"  LLM 응답 JSON 파싱 실패 (user {user_id}): {e}")
        logger.warning(f"  응답: {text[:200]}")
        return None
    except Exception as e:
        logger.error(f"  LLM 호출 실패 (user {user_id}): {e}")
        return None


def analyze_with_llm(passed_logs, client=None):
    """
    Layer 2 메인: LLM으로 회색지대 분석
    
    Args:
        passed_logs: rule_engine에서 통과한 로그 리스트
        client: Anthropic 클라이언트 (없으면 새로 생성)
    
    Returns:
        list of dict: LLM 알림 리스트 (rule_engine 형식과 호환)
    """
    if client is None:
        try:
            client = get_anthropic_client()
        except ValueError as e:
            logger.error(f"LLM 분석 스킵: {e}")
            return []
    
    # 사용자별 그룹핑 (JWT 있는 로그만)
    user_groups = defaultdict(list)
    for log in passed_logs:
        user_id = log.get("user_id")
        if user_id:
            user_groups[user_id].append(log)
    
    if not user_groups:
        return []
    
    alerts = []
    checked_count = 0
    skipped_count = 0
    
    for user_id, user_logs in user_groups.items():
        # 비용 통제: 의심 사용자만
        if not should_check_user(user_logs):
            skipped_count += 1
            continue
        
        checked_count += 1
        logger.info(f"  LLM 분석: user {user_id} ({len(user_logs)}건)")
        
        result = analyze_user_with_llm(client, user_id, user_logs)
        if result:
            # rule_engine 알림 형식과 호환되게 래핑
            log_info = user_logs[0]  # 대표 로그
            alerts.append({
                "log": {
                    "timestamp": log_info.get("@timestamp"),
                    "ip": log_info.get("ip"),
                    "method": log_info.get("method"),
                    "uri": log_info.get("uri"),
                    "status": log_info.get("status"),
                    "user_id": user_id,
                    "jwt_id": log_info.get("jwt_id"),
                    "session_id": log_info.get("session_id")
                },
                "alerts": [result]
            })
    
    logger.info(f"  LLM 검사: {checked_count}명 (스킵 {skipped_count}명)")
    logger.info(f"  LLM 알림: {len(alerts)}건")
    
    return alerts


# ============================================================
# 테스트
# ============================================================

if __name__ == "__main__":
    import sys
    sys.path.insert(0, '/home/ssm-user/uba-analyzer')
    from log_fetcher import get_es_client, fetch_recent_logs
    from rule_engine import analyze_logs
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
    
    print("=== llm_analyzer 테스트 ===\n")
    
    # 1. 로그 + 룰 엔진
    es = get_es_client()
    logs = fetch_recent_logs(es, minutes=240)  # 4시간 (JWT 데이터 포함)
    print(f"[1] 로그 수집: {len(logs)}건")
    
    rule_result = analyze_logs(logs)
    print(f"[2] 룰 엔진 매칭: {rule_result['summary']['rule_matched']}건")
    print(f"    LLM 대상: {len(rule_result['passed_to_llm'])}건\n")
    
    # 2. LLM 분석
    print("[3] LLM 분석 시작")
    try:
        client = get_anthropic_client()
        print(f"    Anthropic 클라이언트 OK\n")
    except ValueError as e:
        print(f"    ERROR: {e}")
        print("    .env 파일에 ANTHROPIC_API_KEY 설정 필요")
        sys.exit(1)
    
    llm_alerts = analyze_with_llm(rule_result['passed_to_llm'], client)
    
    print(f"\n[4] 결과")
    print(f"    LLM 알림: {len(llm_alerts)}건")
    
    if llm_alerts:
        print("\n=== LLM 알림 ===")
        for entry in llm_alerts[:5]:
            log = entry['log']
            for alert in entry['alerts']:
                print(f"\n  [{alert['severity'].upper()}] {alert['rule']}")
                print(f"     reason: {alert['reason']}")
                print(f"     user_id: {log['user_id']}")
                if alert.get('mitre'):
                    print(f"     MITRE: {alert['mitre']}")
                if alert.get('evidence', {}).get('llm_evidence'):
                    for e in alert['evidence']['llm_evidence'][:3]:
                        print(f"     - {e}")
