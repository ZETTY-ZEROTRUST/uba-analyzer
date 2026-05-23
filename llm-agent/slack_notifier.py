"""ZETI UBA — Slack notifier (Incoming Webhook).

Two entry points, matching the two LLM phases:
    - Phase 3a realtime  : ``send_realtime_alert``  — per-alert message (spec 1.8)
    - Phase 3b daily     : ``send_daily_report``    — daily 09:30 KST campaign summary

Webhook URLs come from the environment (never hard-code):
    SLACK_WEBHOOK_URL        (required) — realtime alert channel
    SLACK_WEBHOOK_URL_DAILY  (optional) — daily report channel; falls back to
                                          SLACK_WEBHOOK_URL when unset

Slack delivery never raises into the caller: factor_engine / the LLM pipeline
must keep running even if Slack is down. Both functions return ``bool``.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import requests

logger = logging.getLogger(__name__)

_TIMEOUT = 5.0

# Presentation defaults for attacker_level. The level itself is decided by
# factor_engine; this only supplies the human-readable gloss in the message.
ATTACKER_LEVEL_DESC: dict[str, str] = {
    "L0": "정상 사용자",
    "L2": "내부 사용자 / 권한 오용 가능",
    "L4": "외부 + 키 보유",
    "L4(Slow & Low)": "외부 + 키 보유 (저속 은닉형)",
}


def _post(webhook_url: str, payload: dict[str, Any]) -> bool:
    """POST a payload to a Slack Incoming Webhook. Returns success as bool."""
    if not webhook_url:
        logger.error("Slack webhook URL not configured — message dropped")
        return False
    try:
        resp = requests.post(webhook_url, json=payload, timeout=_TIMEOUT)
    except requests.RequestException as exc:
        logger.error("Slack webhook POST failed: %s", exc)
        return False
    if resp.status_code != 200:
        logger.error("Slack webhook returned %s: %s", resp.status_code, resp.text[:200])
        return False
    return True


# --------------------------------------------------------------------------
# Phase 3a — realtime per-alert message
# --------------------------------------------------------------------------

def _target_line(alert_doc: dict[str, Any]) -> str:
    target_type = str(alert_doc.get("target_type", "")).lower()
    label = "IP" if target_type == "ip" else "User" if target_type == "user" else "Target"
    target_id = alert_doc.get("target_id", "-")
    ip = alert_doc.get("ip_context") or {}
    if not ip:
        return f"Target: {label} {target_id}"
    loc = ip.get("ip_city") or ip.get("ip_country") or "-"
    asn = ip.get("ip_asn", "-")
    org = ip.get("ip_org", "-")
    ip_class = ip.get("ip_class", "unknown")
    return f"Target: {label} {target_id} ({loc}, {asn} {org}, ip_class={ip_class})"


def _score_line(alert_doc: dict[str, Any]) -> str:
    score = alert_doc.get("total_score", "-")
    delta = alert_doc.get("score_delta")
    if delta is None:
        return f"Score: {score}"
    arrow = "↑ +" if delta > 0 else "↓ " if delta < 0 else "→ "
    return f"Score: {score} ({arrow}{delta} 직전 대비)"


def _dominant_line(alert_doc: dict[str, Any]) -> str:
    dom_kr = (
        alert_doc.get("dominant_factor_korean")
        or alert_doc.get("dominant_factor")
        or "-"
    )
    window = alert_doc.get("window", "")
    detail = alert_doc.get("dominant_detail")  # e.g. "unique sub 312명"
    paren = ", ".join(p for p in (f"{window} 윈도우" if window else "", detail) if p)
    return f"Dominant: {dom_kr} ({paren})" if paren else f"Dominant: {dom_kr}"


def _mitre_line(report: dict[str, Any]) -> str:
    items = report.get("mitre_mapping") or []
    if not items:
        return "[MITRE] -"
    rendered = " / ".join(
        f"{m.get('id', '?')} {m.get('name', '')}".strip() for m in items
    )
    return f"[MITRE] {rendered}"


def _cve_line(report: dict[str, Any]) -> str:
    items = report.get("cve_mapping") or []
    if not items:
        return "[CVE] -"
    rendered = " / ".join(
        f"{c.get('id', '?')} ({c.get('rationale', '')})".strip() for c in items
    )
    return f"[CVE] {rendered}"


def _similar_cases_block(report: dict[str, Any]) -> list[str]:
    items = report.get("similar_cases") or []
    if not items:
        return []
    lines = []
    for c in items:
        case = c.get("case", "?")
        sim = c.get("similarity", "")
        lines.append(f"[유사 사례] {case} ({sim})" if sim else f"[유사 사례] {case}")
    return lines


def build_realtime_message(alert_doc: dict[str, Any]) -> str:
    """Render the Phase 3a realtime alert text (spec 1.8 layout).

    ``alert_doc`` is the document written to ``uba-alerts-{date}``:
    factor_engine fields (target_type, target_id, total_score, score_delta,
    dominant_factor[/_korean], attacker_level, data_exfiltration_detected,
    window, ip_context) merged with the validated ``llm_report`` object.
    Missing fields degrade gracefully rather than raising.
    """
    report = alert_doc.get("llm_report") or {}

    lines: list[str] = ["🚨 ZETI 인시던트 알람", ""]
    lines.append(_target_line(alert_doc))
    lines.append(_score_line(alert_doc))
    lines.append(_dominant_line(alert_doc))

    level = alert_doc.get("attacker_level", "-")
    desc = ATTACKER_LEVEL_DESC.get(level)
    lines.append(f"공격자 등급: {level} ({desc})" if desc else f"공격자 등급: {level}")

    if alert_doc.get("data_exfiltration_detected"):
        lines.append("🔓 데이터 유출 탐지됨")

    behavior = (
        report.get("behavior_analysis_korean")
        or report.get("behavior_analysis")
        or "-"
    )
    lines += ["", "[행위 분석]", behavior, ""]

    lines.append(_mitre_line(report))
    lines.append(_cve_line(report))
    lines += _similar_cases_block(report)

    nat = report.get("nat_judgment") or alert_doc.get("nat_judgment") or {}
    if nat.get("applicable"):
        verdict = nat.get("verdict", "n/a")
        rationale = nat.get("rationale", "")
        lines.append(f"[NAT 판정] {verdict} — {rationale}".rstrip(" —"))

    actions = report.get("recommended_actions") or []
    if actions:
        lines += ["", "[추천 액션]"]
        lines += [f"{i}. {a}" for i, a in enumerate(actions, start=1)]

    return "\n".join(lines)


def send_realtime_alert(
    alert_doc: dict[str, Any],
    webhook_url: str | None = None,
) -> bool:
    """Send a Phase 3a realtime incident alert to Slack."""
    url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL", "")
    message = build_realtime_message(alert_doc)
    return _post(url, {"text": message, "unfurl_links": False})


# --------------------------------------------------------------------------
# Phase 3b — daily campaign summary
# --------------------------------------------------------------------------

_PATTERN_LABEL = {
    "S4": "S4 (자격증명 탈취 + 점진적 수집)",
    "S6": "S6 (Slow & Low 유출)",
    "미분류": "미분류",
}


def build_daily_message(intel_doc: dict[str, Any]) -> str:
    """Render the Phase 3b daily intelligence summary text.

    ``intel_doc`` is the ``uba-intelligence-{date}`` document with
    report_type=daily: campaign_summary, timeline, attacker_assessment,
    pattern_analysis, risk_assessment, forward_recommendations.
    """
    lines: list[str] = ["📊 ZETI 일일 인텔리전스 리포트", ""]

    start = intel_doc.get("time_range_start", "")
    end = intel_doc.get("time_range_end", "")
    if start or end:
        lines.append(f"기간: {start} ~ {end}")

    pattern = intel_doc.get("pattern_analysis", "-")
    lines.append(f"패턴: {_PATTERN_LABEL.get(pattern, pattern)}")
    lines.append("")

    lines += ["[캠페인 요약]", intel_doc.get("campaign_summary", "-"), ""]

    lines += ["[공격자 평가]", intel_doc.get("attacker_assessment", "-"), ""]

    risk = intel_doc.get("risk_assessment") or {}
    subs = risk.get("affected_subs", 0)
    exposure = risk.get("estimated_data_exposure_bytes", 0)
    lines.append(f"[리스크] 영향 sub {subs}명 · 추정 유출량 {_human_bytes(exposure)}")

    timeline = intel_doc.get("timeline") or []
    if timeline:
        lines += ["", "[타임라인]"]
        for ev in timeline:
            ts = ev.get("timestamp", "")
            lines.append(f"- {ts} {ev.get('event', '')}".rstrip())

    recs = intel_doc.get("forward_recommendations") or []
    if recs:
        lines += ["", "[향후 24h 모니터링 권고]"]
        lines += [f"{i}. {r}" for i, r in enumerate(recs, start=1)]

    return "\n".join(lines)


def _human_bytes(n: int) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}GB"


def send_daily_report(
    intel_doc: dict[str, Any],
    webhook_url: str | None = None,
) -> bool:
    """Send the Phase 3b daily intelligence summary to Slack."""
    url = (
        webhook_url
        or os.environ.get("SLACK_WEBHOOK_URL_DAILY")
        or os.environ.get("SLACK_WEBHOOK_URL", "")
    )
    message = build_daily_message(intel_doc)
    return _post(url, {"text": message, "unfurl_links": False})
