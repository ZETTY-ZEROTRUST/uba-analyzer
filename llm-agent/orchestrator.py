"""ZETI UBA — ReAct orchestrator (Phase 3a realtime + Phase 3b batch).

This is the executable that wires the pieces together. ``tools.py`` and the
``prompts/`` modules are only declarations; this module actually runs the loop:

    factor_engine alert
        → TriggerGate (score floor + throttle + cost guard)        [3a only]
        → Anthropic Messages API  (Haiku 3a / Sonnet 3b)
        → tool_use blocks routed to the 3 MCP servers via MCPRouter
        → loop up to N iterations
        → final JSON parsed
        → grounding.validate_llm_output  (strips hallucinated MITRE/CVE ids)
        → write uba-alerts-{date} / uba-intelligence-{date}
        → Slack (realtime immediately / daily summary)

LLM never computes scores or block decisions — those stay with factor_engine.

CLI (smoke test)::

    python orchestrator.py --phase 3a --input alert.json
    python orchestrator.py --phase 3b --input bundle.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# llm-agent/ and prompts/ are sibling dirs of flat modules — put both on path.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent / "prompts"))

import config  # noqa: E402
import grounding  # noqa: E402
import phase_3a  # noqa: E402
import phase_3b  # noqa: E402
import slack_notifier  # noqa: E402
from anthropic import AsyncAnthropic  # noqa: E402
from elasticsearch import Elasticsearch  # noqa: E402
from mcp_router import MCPRouter  # noqa: E402
from risk_doc_adapter import risk_doc_to_alert  # noqa: E402
from throttle import TriggerGate  # noqa: E402
from tools import ALL_TOOLS  # noqa: E402

logger = logging.getLogger("zeti.orchestrator")

KST = timezone(timedelta(hours=9))


def _kst_now() -> datetime:
    return datetime.now(KST)


def _index_for(prefix: str, when: datetime | None = None) -> str:
    """uba-alerts-2026.05.17 style daily index name (KST)."""
    return f"{prefix}-{(when or _kst_now()).strftime('%Y.%m.%d')}"


def _extract_text(blocks: list[Any]) -> str:
    return "".join(getattr(b, "text", "") for b in blocks if getattr(b, "type", None) == "text")


def _parse_json(text: str) -> dict[str, Any]:
    """Parse the model's final answer, tolerating stray code fences."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[-1]
        if cleaned.rstrip().endswith("```"):
            cleaned = cleaned.rstrip()[:-3]
    try:
        return json.loads(cleaned)
    except (json.JSONDecodeError, ValueError):
        # last resort: grab the outermost {...}
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if 0 <= start < end:
            return json.loads(cleaned[start : end + 1])
        raise


class ReActOrchestrator:
    """Runs the Anthropic Messages API ReAct loop against the 3 MCP servers."""

    def __init__(self) -> None:
        self.client = AsyncAnthropic()  # reads ANTHROPIC_API_KEY
        self.router = MCPRouter()
        self.gate = TriggerGate(config.STATE_PATH)
        self._es: Elasticsearch | None = None

    # -- lifecycle ----------------------------------------------------------

    async def __aenter__(self) -> "ReActOrchestrator":
        await self.router.__aenter__()
        es_cfg = config.es_write_config()
        self._es = Elasticsearch(
            es_cfg["url"],
            api_key=es_cfg["api_key"],
            verify_certs=es_cfg["verify"],
            request_timeout=15,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.router.__aexit__(*exc)
        if self._es is not None:
            self._es.close()

    # -- core loop ----------------------------------------------------------

    async def _react_loop(
        self, model: str, system_prompt: str, user_prompt: str, max_iters: int
    ) -> dict[str, Any]:
        """Drive one ReAct conversation and return the parsed final JSON."""
        messages: list[dict[str, Any]] = [{"role": "user", "content": user_prompt}]
        system = [{"type": "text", "text": system_prompt,
                   "cache_control": {"type": "ephemeral"}}]

        final_text = ""
        # max_iters tool rounds + 1 forced no-tool round to guarantee an answer.
        for step in range(max_iters + 1):
            force_final = step == max_iters
            kwargs: dict[str, Any] = {
                "model": model,
                "max_tokens": config.MAX_TOKENS,
                "system": system,
                "messages": messages,
            }
            if not force_final:
                kwargs["tools"] = ALL_TOOLS

            resp = await self.client.messages.create(**kwargs)
            messages.append({"role": "assistant",
                             "content": [b.model_dump() for b in resp.content]})

            if resp.stop_reason != "tool_use":
                final_text = _extract_text(resp.content)
                break

            tool_results: list[dict[str, Any]] = []
            for block in resp.content:
                if getattr(block, "type", None) != "tool_use":
                    continue
                logger.info("tool_use %s %s", block.name, block.input)
                result = await self.router.dispatch(block.name, dict(block.input))
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result,
                })
            messages.append({"role": "user", "content": tool_results})

        if not final_text:
            raise RuntimeError("ReAct loop produced no final text output")
        return _parse_json(final_text)

    # -- ES / Slack ---------------------------------------------------------

    def _write(self, index: str, doc: dict[str, Any]) -> str | None:
        try:
            resp = self._es.index(index=index, document=doc)  # type: ignore[union-attr]
            return resp.get("_id")
        except Exception as exc:  # noqa: BLE001 — a write 403 must not lose the report
            logger.error("ES write to %s failed: %s", index, exc)
            return None

    # -- Phase 3a -----------------------------------------------------------

    async def run_phase_3a(self, risk_doc: dict[str, Any], *,
                           sample_logs: list[dict[str, Any]] | None = None,
                           p99_today: float | None = None) -> dict[str, Any] | None:
        """Analyse one uba-risk-scores risk doc.

        risk_doc_adapter 가 risk doc 을 phase_3a alert 형태로 변환한 뒤
        gate → ReAct → grounding → uba-alerts 색인 → Slack. trigger gate 가
        억제하면 None 을 반환한다.
        """
        alert = risk_doc_to_alert(risk_doc, sample_logs=sample_logs, p99_today=p99_today)
        decision = self.gate.evaluate(alert)
        logger.info("Phase 3a gate: run=%s — %s", decision["run"], decision["reason"])
        if not decision["run"]:
            return None

        prev_score = self.gate.previous_score(alert)
        self.gate.commit(alert)

        report = await self._react_loop(
            config.HAIKU_MODEL,
            phase_3a.SYSTEM_PROMPT,
            phase_3a.build_user_prompt(alert),
            config.PHASE_3A_MAX_ITERS,
        )
        report, validation = grounding.validate_llm_output(
            report, self._es, nvd_api_key=config.NVD_API_KEY  # type: ignore[arg-type]
        )

        dom = alert.get("dominant_factor", "")
        total = alert.get("total_score")
        alert_doc: dict[str, Any] = {
            "@timestamp": _kst_now().isoformat(),
            "phase": "3a",
            "model": config.HAIKU_MODEL,
            "target_type": alert.get("target_type"),
            "target_id": alert.get("target_id"),
            "total_score": total,
            "score_delta": (total - prev_score) if (prev_score is not None and total is not None) else None,
            "dominant_factor": dom,
            "dominant_factor_korean": phase_3a.FACTOR_NAMES_KR.get(dom, dom),
            "window": alert.get("window"),
            # factor_engine truth — never overridden by the LLM echo.
            "attacker_level": alert.get("attacker_level"),
            "data_exfiltration_detected": alert.get("data_exfiltration_detected"),
            "ip_context": alert.get("ip_context"),
            "factor_scores": alert.get("factor_scores"),
            "llm_report": report,
            "grounding_validation": asdict(validation),
            "trigger_reason": decision["reason"],
        }

        alert_doc["_id"] = self._write(_index_for("uba-alerts"), alert_doc)
        if slack_notifier.send_realtime_alert(alert_doc):
            logger.info("Phase 3a Slack alert sent")
        else:
            logger.warning("Phase 3a Slack alert NOT sent")
        return alert_doc

    # -- Phase 3b -----------------------------------------------------------

    async def run_phase_3b(
        self,
        report_type: str,
        time_range_start: str,
        time_range_end: str,
        alerts: list[dict[str, Any]],
        score_timeseries: list[dict[str, Any]],
        sub_threshold_activity: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Reconstruct campaigns over a window. report_type is 'hourly'|'daily'."""
        report = await self._react_loop(
            config.SONNET_MODEL,
            phase_3b.SYSTEM_PROMPT,
            phase_3b.build_user_prompt(
                report_type, time_range_start, time_range_end,
                alerts, score_timeseries, sub_threshold_activity,
            ),
            config.PHASE_3B_MAX_ITERS,
        )
        report, validation = grounding.validate_llm_output(
            report, self._es, nvd_api_key=config.NVD_API_KEY  # type: ignore[arg-type]
        )

        intel_doc: dict[str, Any] = {
            "@timestamp": _kst_now().isoformat(),
            "phase": "3b",
            "model": config.SONNET_MODEL,
            "report_type": report_type,
            "grounding_validation": asdict(validation),
            **report,
        }
        intel_doc["_id"] = self._write(_index_for("uba-intelligence"), intel_doc)

        if report_type == "daily":
            if slack_notifier.send_daily_report(intel_doc):
                logger.info("Phase 3b daily Slack report sent")
            else:
                logger.warning("Phase 3b daily Slack report NOT sent")
        return intel_doc


# --- CLI smoke test --------------------------------------------------------

async def _main() -> int:
    parser = argparse.ArgumentParser(description="ZETI UBA ReAct orchestrator")
    parser.add_argument("--phase", choices=["3a", "3b"], required=True)
    parser.add_argument("--input", required=True, help="JSON file: 3a=alert doc, 3b=bundle")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))

    async with ReActOrchestrator() as orch:
        if args.phase == "3a":
            result = await orch.run_phase_3a(payload)
            if result is None:
                print("suppressed by trigger gate")
                return 0
        else:
            result = await orch.run_phase_3b(
                payload.get("report_type", "hourly"),
                payload["time_range_start"],
                payload["time_range_end"],
                payload.get("alerts", []),
                payload.get("score_timeseries", []),
                payload.get("sub_threshold_activity", []),
            )
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
