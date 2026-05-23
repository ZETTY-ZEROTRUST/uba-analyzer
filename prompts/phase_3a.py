"""ZETI UBA — Phase 3a prompt (single-alert realtime, claude-haiku-4-5).

Spec contract (v12 재정합):
    - LLM does NOT compute scores or attacker_level — those come from factor_engine.
    - LLM produces incident report JSON, MITRE/CVE mappings (real IDs only),
      NAT judgment when ip_user_diversity dominant, recommended actions.
    - Korean factor names in prose; English snake_case keys as table-only aliases.
    - ★ v12: 팩터 키는 영문 의미명 7종 (구 F-코드 F2/F6/F9 폐기).
      입력 alert 은 risk_doc_adapter 가 uba-risk-scores risk doc 에서 변환한 것.

Usage:
    from phase_3a import SYSTEM_PROMPT, build_user_prompt, OUTPUT_SCHEMA
    msg = anthropic.messages.create(
        model="claude-haiku-4-5-20251001",
        system=[{"type": "text", "text": SYSTEM_PROMPT,
                 "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": build_user_prompt(alert)}],
        tools=[ES_TOOL, MITRE_TOOL, NVD_TOOL],
        max_tokens=4096,
    )
"""

from __future__ import annotations

import json
from typing import Any

# --- v12 영문 의미명 팩터 키 → 한국어 이름.
# LLM 본문은 한국어 이름 사용, 영문 키는 표 안에서만 별칭.
FACTOR_NAMES_KR: dict[str, str] = {
    "token_violation": "토큰규격위반",
    "request_burst": "요청수급증",
    "token_replay": "토큰재현(Replay)",
    "response_size_burst": "응답크기급증",
    "ip_user_diversity": "IP-사용자다양성",
    "response_sensitivity": "응답민감도",
    "cumulative_exfil": "누적유출량",
}
# Override 팩터 — throttle 우회, Phase 3a 에서 특별 처리.
OVERRIDE_FACTORS = {"ip_user_diversity", "response_sensitivity"}


SYSTEM_PROMPT = """당신은 ZETI SOC의 인시던트 분석가입니다.

# 역할 경계 (반드시 지킬 것)
- 점수 산출은 하지 않습니다. 모든 팩터 점수, total_score, dominant_factor, attacker_level, data_exfiltration_detected는 factor_engine이 이미 계산해서 입력으로 줍니다.
- 차단/허용 결정은 하지 않습니다. recommended_actions에 권고만 적습니다.
- 한국어로 작성합니다. 본문에는 한국어 팩터 이름(예: "IP-사용자다양성")을 직접 사용하고, 영문 키는 표 안에서만 별칭으로 씁니다.

# 사용 가능한 도구 (ReAct, 최대 5회 호출)
1. query_elasticsearch(index, query, time_range, size)
   - 알람 컨텍스트를 능동적으로 보강할 때만 호출합니다.
2. search_mitre_attack(keywords)
   - 로컬 캐시된 mitre-attack 인덱스에서 technique/sub-technique를 검색합니다.
3. search_nvd_cve(query, cvss_min)
   - NVD에서 관련 CVE를 검색합니다. 핵심 CVE는 로컬 캐시 우선.

# 4단계 분석 절차
1단계 — 컨텍스트 보강 (선택적)
- dominant_factor가 ip_user_diversity (IP-사용자다양성)이고 ip_class가 cgnat_kr 또는 unknown일 때 → 해당 IP의 직전 24h UA 다양성/시간 분포/baseline 조회.
- dominant_factor가 response_sensitivity (응답민감도)일 때 → target의 직전 1h endpoint별 호출 패턴 조회.
- dominant_factor가 cumulative_exfil (누적유출량)일 때 → target의 직전 3d 응답 바이트 시계열 조회.
- dominant_factor가 token_replay (토큰재현)일 때 → 해당 jti가 관측된 ip_class/ip_country 집합 조회.
- 그 외 dominant_factor에서는 굳이 추가 조회하지 마세요(latency/비용 가드).

2단계 — MITRE / CVE 매핑
- search_mitre_attack 키워드 가이드:
  · ip_user_diversity(IP-사용자다양성) → "credential access", "T1606", "T1110"
  · response_sensitivity(응답민감도) → "exfiltration", "T1041", "collection"
  · cumulative_exfil(누적유출량) → "exfiltration over c2", "T1041", "T1567"
  · token_violation(토큰규격위반) → "valid accounts", "T1078", "modify authentication process"
  · request_burst(요청수급증) → "brute force", "T1110", "scanning"
  · token_replay(토큰재현) → "T1550", "use alternate authentication material", "T1606"
  · response_size_burst(응답크기급증) → "T1530", "data from cloud storage object"
- search_nvd_cve 호출 시 cvss_min=7.0 기본, dominant_factor 키워드로 검색.
- 검색 결과에 없는 ID는 절대 만들어내지 않습니다.

3단계 — JSON 출력
- 반드시 아래 OUTPUT_SCHEMA(키와 타입)와 동일한 구조의 JSON 하나만 출력합니다.
- behavior_analysis: 3~5줄. 관리자가 30초 안에 상황 파악 가능하게. 본문에 한국어 팩터 이름 사용.
- nat_judgment.applicable: dominant_factor == ip_user_diversity(IP-사용자다양성)일 때만 true. 그 외에는 false이고 verdict는 "n/a".
- similar_cases는 실제 알려진 사고만(예: 쿠팡 2025-06 사고 등). 모르면 빈 배열.

4단계 — 자가 검증
- mitre_mapping의 모든 id가 search_mitre_attack 결과로 확인된 것인지 다시 확인합니다(불확실하면 재호출 또는 항목 제외).
- cve_mapping의 모든 id가 search_nvd_cve 결과에 있었는지 확인합니다.
- 매핑이 불확실하면 해당 항목을 제외하고 빈 배열로 둡니다. 환각 금지.

# 출력 규칙
- 자연어 설명은 JSON 앞뒤에 절대 붙이지 않습니다.
- 마크다운 코드펜스를 쓰지 않습니다. JSON 객체 하나만 반환합니다.
"""


OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "behavior_analysis",
        "mitre_mapping",
        "cve_mapping",
        "attacker_level",
        "data_exfiltration_detected",
        "attack_phase",
        "nat_judgment",
        "similar_cases",
        "recommended_actions",
    ],
    "properties": {
        "behavior_analysis": {"type": "string"},
        "mitre_mapping": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "name", "rationale"],
                "properties": {
                    "id": {"type": "string", "pattern": r"^T\d{4}(\.\d{3})?$"},
                    "name": {"type": "string"},
                    "rationale": {"type": "string"},
                },
            },
        },
        "cve_mapping": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "rationale"],
                "properties": {
                    "id": {"type": "string", "pattern": r"^CVE-\d{4}-\d{4,}$"},
                    "rationale": {"type": "string"},
                },
            },
        },
        "attacker_level": {"enum": ["L0", "L2", "L4", "L4(Slow & Low)"]},
        "data_exfiltration_detected": {"type": "boolean"},
        "attack_phase": {
            "enum": [
                "recon",
                "initial_access",
                "credential_access",
                "collection",
                "exfiltration",
                "impact",
            ]
        },
        "nat_judgment": {
            "type": "object",
            "required": ["applicable", "verdict", "rationale"],
            "properties": {
                "applicable": {"type": "boolean"},
                "verdict": {"enum": ["normal_nat", "attack", "uncertain", "n/a"]},
                "rationale": {"type": "string"},
            },
        },
        "similar_cases": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["case", "similarity", "year"],
                "properties": {
                    "case": {"type": "string"},
                    "similarity": {"type": "string"},
                    "year": {"type": "integer"},
                },
            },
        },
        "recommended_actions": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 3,
            "maxItems": 5,
        },
    },
}


def _factor_table(factor_breakdown: dict[str, float], window: str | None,
                  iud_meta: dict[str, Any] | None) -> str:
    """7 팩터 점수 표. ip_user_diversity 행에는 윈도우/soft cap 메타를 덧붙인다."""
    lines = []
    for key, kr in FACTOR_NAMES_KR.items():
        score = factor_breakdown.get(key, 0)
        suffix = ""
        if key == "ip_user_diversity" and iud_meta:
            capped = iud_meta.get("capped", False)
            suffix = f"   ← window={window}, soft_cap_applied={capped}"
        lines.append(f"- {kr} ({key}): {score}{suffix}")
    return "\n".join(lines)


def build_user_prompt(alert: dict[str, Any]) -> str:
    """Phase 3a per-alert user prompt.

    ``alert`` 은 risk_doc_adapter.risk_doc_to_alert() 출력. 필요한 키:
        target_type, target_id, total_score, dominant_factor (영문 의미명 키),
        attacker_level, data_exfiltration_detected, window (윈도우 크기),
        factor_scores: {7 영문 의미명 키: int}  (risk doc 의 factor_breakdown),
        ip_context: {ip_class, ip_asn, ip_org, ip_country, is_nat_whitelisted},
        ip_user_diversity_meta (dict | None),
        sample_logs: 직전 로그 dict 리스트 (호출자가 ~5건으로 미리 trim).
    """
    dom = alert["dominant_factor"]
    dom_kr = FACTOR_NAMES_KR.get(dom, dom)
    ip = alert.get("ip_context") or {}
    sample = alert.get("sample_logs") or []

    return f"""# 알람 정보
- target_type: {alert['target_type']}
- target_id: {alert['target_id']}
- total_score: {alert['total_score']}
- dominant_factor: {dom_kr} ({dom})
- attacker_level: {alert['attacker_level']}
- data_exfiltration_detected: {alert['data_exfiltration_detected']}
- window: {alert['window']}

# 팩터별 점수
{_factor_table(alert.get('factor_scores', {}), alert.get('window'), alert.get('ip_user_diversity_meta'))}

# IP 컨텍스트
- ip_class: {ip.get('ip_class', 'unknown')}
- ip_asn: {ip.get('ip_asn', '-')}
- ip_org: {ip.get('ip_org', '-')}
- ip_country: {ip.get('ip_country', '-')}
- is_nat_whitelisted: {ip.get('is_nat_whitelisted', False)}

# 샘플 로그 (직전 5분, 최대 5건)
{json.dumps(sample, ensure_ascii=False, indent=2)}

위 입력에 대해 4단계 절차를 수행하고 OUTPUT_SCHEMA 그대로의 JSON 객체 하나만 반환하세요.
"""
