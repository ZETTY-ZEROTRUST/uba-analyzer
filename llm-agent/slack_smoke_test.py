#!/usr/bin/env python3
"""ZETI UBA — Slack notifier smoke test.

Fires one realtime alert (spec 1.8 scenario) and one daily report at a real
Slack Incoming Webhook so you can eyeball the formatting in the channel.

Run on the UBA server (slack_notifier.py + requests live there):
    aws ssm start-session --target i-0e06820c477644613
    python3 /opt/zeti-uba/llm-agent/slack_smoke_test.py
The Webhook URL is read with getpass — never echoed or logged.
"""

from __future__ import annotations

import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from slack_notifier import send_realtime_alert, send_daily_report  # noqa: E402

# --- spec 1.8 scenario — F9 IP enumeration -------------------------------

ALERT_DOC = {
    "target_type": "ip",
    "target_id": "203.0.113.42",
    "total_score": 100,
    "score_delta": 30,
    "dominant_factor": "F9",
    "dominant_factor_korean": "IP-사용자다양성",
    "dominant_factor_alias": "F9",
    "attacker_level": "L4",
    "data_exfiltration_detected": True,
    "window": "5분",
    "dominant_detail": "unique sub 312명",
    "ip_context": {
        "ip_city": "도쿄", "ip_country": "JP", "ip_asn": "AS16509",
        "ip_org": "AWS", "ip_class": "cloud",
    },
    "llm_report": {
        "behavior_analysis_korean": (
            "단일 IP에서 5분간 312명의 서로 다른 user ID로 /api/addresses 호출. "
            "응답 누적 320KB. 정상 분포(IP당 5분 unique sub 평균 1.2 ± 0.4)에서 "
            "z-score 200+. KMS 검증 + Spring Security @PreAuthorize 모두 통과한 "
            "정상 서명 토큰."
        ),
        "mitre_mapping": [
            {"id": "T1606.001", "name": "Web Cookies", "rationale": "서명 토큰 위조"},
            {"id": "T1041", "name": "Exfiltration Over C2 Channel",
             "rationale": "응답 데이터 유출"},
        ],
        "cve_mapping": [
            {"id": "CVE-2025-6950", "rationale": "쿠팡 JWT 서명키 탈취 사고"},
        ],
        "similar_cases": [
            {"case": "쿠팡 2025-06 사고",
             "similarity": "94.8% 유사 — sub=path 일치 위조 + enumeration",
             "year": 2025},
        ],
        "recommended_actions": [
            "해당 IP 차단 검토 (방화벽 / WAF)",
            "KMS 서명키 회전 (alias/jwt-signing-key-external)",
            "auth-server 키 디스크 노출 점검",
            "영향 받은 312 sub 통지 검토",
        ],
        "nat_judgment": {
            "applicable": True, "verdict": "attack",
            "rationale": "NAT 화이트리스트 미해당 — 공격으로 판정",
        },
    },
}

INTEL_DOC = {
    "report_type": "daily",
    "time_range_start": "2026-05-15T00:00:00+09:00",
    "time_range_end": "2026-05-16T00:00:00+09:00",
    "campaign_summary": (
        "지난 24시간 동안 외부 IP 대역(203.0.113.0/24)에서 유효 서명 토큰을 사용한 "
        "대규모 enumeration 캠페인이 관측됨. 토큰공유 → IP-사용자다양성 → "
        "응답민감도/누적유출량으로 전이."
    ),
    "attacker_assessment": (
        "공격자는 유효 서명 토큰을 보유한 L4 등급. KMS·Spring Security 검증을 "
        "통과하는 정상 토큰으로 IDOR/enumeration 수행."
    ),
    "pattern_analysis": "S4",
    "timeline": [
        {"timestamp": "2026-05-15T04:00:00+09:00", "event": "203.0.113.10 토큰공유 신호 첫 발생"},
        {"timestamp": "2026-05-15T10:00:00+09:00", "event": "IP-사용자다양성 급증 — enumeration 본격화"},
        {"timestamp": "2026-05-15T18:00:00+09:00", "event": "응답민감도·누적유출량으로 전이"},
    ],
    "risk_assessment": {"affected_subs": 312, "estimated_data_exposure_bytes": 327680},
    "forward_recommendations": [
        "203.0.113.0/24 대역 WAF 차단 검토",
        "KMS 서명키 회전 (alias/jwt-signing-key-external)",
        "영향 sub 312명 통지 검토",
    ],
}


def main() -> int:
    url = getpass.getpass("Slack Webhook URL: ").strip()
    if not url.startswith("https://hooks.slack.com/"):
        print("WARN: Webhook URL 형식이 예상과 다릅니다 (https://hooks.slack.com/...)")

    print("realtime alert 전송 중...")
    ok1 = send_realtime_alert(ALERT_DOC, webhook_url=url)
    print("  ->", "OK" if ok1 else "FAIL")

    print("daily report 전송 중...")
    ok2 = send_daily_report(INTEL_DOC, webhook_url=url)
    print("  ->", "OK" if ok2 else "FAIL")

    if ok1 and ok2:
        print("\n완료. Slack 채널에서 메시지 2건 확인하세요.")
        return 0
    print("\n실패 — Webhook URL / 네트워크 확인.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
