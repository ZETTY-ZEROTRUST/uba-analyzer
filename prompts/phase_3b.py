"""ZETI UBA — Phase 3b prompt (batch campaign reconstruction, claude-sonnet-4-6).

Runs hourly + daily 09:00 KST. Input is the bundle of alerts within the time
window + score time-series + sub-threshold (sub-50 score) activity.

Output goes to ``uba-intelligence-{date}`` index; Slack summary daily 09:30 KST.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from phase_3a import FACTOR_NAMES_KR  # reuse Korean factor names

ReportType = Literal["hourly", "daily"]


SYSTEM_PROMPT = """당신은 ZETI SOC의 인텔리전스 분석가입니다.

# 임무
주어진 시간 범위 안의 알람들을 묶어 "캠페인(공격 서사)" 단위로 재구성합니다. 관리자가 5분 안에 "이 시간대에 무슨 일이 있었는지" 파악할 수 있어야 합니다.

# 역할 경계
- 점수 재산정은 하지 않습니다. 입력의 total_score와 dominant_factor는 그대로 신뢰합니다.
- 한국어로 작성합니다. 본문에 한국어 팩터 이름을 사용하고, F-코드는 표/괄호에서만 별칭으로 씁니다.
- 차단 결정은 하지 않습니다. forward_recommendations는 다음 24h 모니터링 신호 권고입니다.

# 사용 가능한 도구 (ReAct, 최대 8회 호출)
1. query_elasticsearch — 의심 신호의 baseline 비교, 같은 IP/sub의 다른 시간대 활동 조회
2. search_mitre_attack — 캠페인 전반의 tactic 흐름을 매핑
3. search_nvd_cve — 캠페인이 노리는 것으로 보이는 취약점 매핑

# 3단계 분석 절차
1단계 — 클러스터링
- 같은 IP 또는 같은 sub로 묶이는 알람을 캠페인 후보로 그룹화합니다.
- 시간 순서대로 timeline을 만듭니다. sub-threshold 신호도 약한 정황으로 포함시킵니다.

2단계 — 시나리오 매칭
- S4 (자격증명 탈취 + 점진적 데이터 수집): 토큰공유/IP-사용자다양성 → 응답민감도/누적유출량으로 옮겨가는 패턴
- S6 (Slow & Low 유출): 24h+ 지속되는 낮은 점수의 누적유출량 신호
- 위 두 시나리오에 해당하지 않으면 "미분류"
- 매칭 근거를 attacker_assessment에 명시합니다.

3단계 — JSON 출력
- 반드시 OUTPUT_SCHEMA 구조의 JSON 객체 하나만 반환합니다.
- 코드펜스/자연어 설명을 앞뒤에 붙이지 않습니다.
- 매핑이 불확실한 MITRE/CVE는 항목에서 제외합니다(환각 금지).
"""


OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "report_type",
        "time_range_start",
        "time_range_end",
        "campaign_summary",
        "timeline",
        "attacker_assessment",
        "pattern_analysis",
        "risk_assessment",
        "mitre_mapping",
        "cve_mapping",
        "forward_recommendations",
    ],
    "properties": {
        "report_type": {"enum": ["hourly", "daily"]},
        "time_range_start": {"type": "string"},
        "time_range_end": {"type": "string"},
        "campaign_summary": {"type": "string"},
        "timeline": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["timestamp", "event"],
                "properties": {
                    "timestamp": {"type": "string"},
                    "event": {"type": "string"},
                    "alert_id": {"type": ["string", "null"]},
                },
            },
        },
        "attacker_assessment": {"type": "string"},
        "pattern_analysis": {"enum": ["S4", "S6", "미분류"]},
        "risk_assessment": {
            "type": "object",
            "required": ["affected_subs", "estimated_data_exposure_bytes"],
            "properties": {
                "affected_subs": {"type": "integer"},
                "estimated_data_exposure_bytes": {"type": "integer"},
            },
        },
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
        "forward_recommendations": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 3,
            "maxItems": 5,
        },
    },
}


def build_user_prompt(
    report_type: ReportType,
    time_range_start: str,
    time_range_end: str,
    alerts: list[dict[str, Any]],
    score_timeseries: list[dict[str, Any]],
    sub_threshold_activity: list[dict[str, Any]],
) -> str:
    """Render the per-window user prompt for Phase 3b.

    ``alerts`` are already-emitted Phase 3a outputs within the window.
    ``score_timeseries`` is a small (≤120 points) summary of per-bucket scores.
    ``sub_threshold_activity`` is suspicion noise below the 50-score gate that
    the LLM should weave into the campaign timeline.
    """
    return f"""# 시간 범위
- report_type: {report_type}
- start: {time_range_start}
- end:   {time_range_end}

# 알람 ({len(alerts)}건)
{json.dumps(alerts, ensure_ascii=False, indent=2)}

# 점수 시계열 (버킷별 total_score 요약)
{json.dumps(score_timeseries, ensure_ascii=False, indent=2)}

# 50점 미만 누적 활동 (약한 신호)
{json.dumps(sub_threshold_activity, ensure_ascii=False, indent=2)}

# 팩터 이름 참고 (본문에 사용)
{json.dumps(FACTOR_NAMES_KR, ensure_ascii=False)}

위 입력에 대해 3단계 절차를 수행하고 OUTPUT_SCHEMA 그대로의 JSON 객체 하나만 반환하세요.
"""
