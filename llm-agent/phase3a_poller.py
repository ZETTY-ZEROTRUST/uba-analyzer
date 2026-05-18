"""phase3a_poller.py — uba-risk-scores 폴링 → Phase 3a 트리거 (빠진 호출자).

Phase 2(risk_scorer)가 uba-risk-scores 에 위험 점수를 적재하면, 이 폴러가
주기적으로 그 인덱스를 훑어 알람 후보(total_score >= max(p99_today, 50))를
골라 ReActOrchestrator.run_phase_3a 로 넘긴다. 중복/과호출은 orchestrator 안의
TriggerGate(throttle)가 막는다.

흐름:
    uba-risk-scores (Phase 2 출력)  ─조회→  total_score >= floor 후보
    uba-baseline / 오늘 total_score 분포  ─조회→  p99_today
        → ReActOrchestrator.run_phase_3a(risk_doc, p99_today=...)
        → (gate 통과 시) Haiku ReAct → uba-alerts 색인 → Slack

실행 (UBA EC2):
    python phase3a_poller.py --since 10              # 최근 10분 risk doc 1회 처리
    python phase3a_poller.py --since 10 --loop 60    # 60초 간격 상시 폴링
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# llm-agent/ 를 path 에 — config / orchestrator / throttle 를 형제 모듈로 import.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

import config  # noqa: E402
from elasticsearch import Elasticsearch  # noqa: E402
from orchestrator import ReActOrchestrator  # noqa: E402
from throttle import SCORE_FLOOR_MIN  # noqa: E402

logger = logging.getLogger("zeti.phase3a_poller")

RISK_INDEX = "uba-risk-scores-*"


def _es() -> Elasticsearch:
    cfg = config.es_write_config()
    return Elasticsearch(cfg["url"], api_key=cfg["api_key"],
                         verify_certs=cfg["verify"], request_timeout=15)


def fetch_p99_today(es: Elasticsearch) -> float:
    """오늘(UTC) 적재된 risk doc 의 total_score 분포에서 p99 를 구한다.

    트리거 score floor = max(p99_today, 50). 조회 실패 시 0 → floor = 50.
    """
    start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0).isoformat()
    try:
        resp = es.search(
            index=RISK_INDEX, size=0,
            query={"range": {"computed_at": {"gte": start}}},
            aggs={"p99": {"percentiles": {"field": "total_score", "percents": [99]}}},
        )
        return float(resp["aggregations"]["p99"]["values"].get("99.0") or 0.0)
    except Exception as exc:  # noqa: BLE001 — p99 없으면 floor=50 으로 graceful degrade
        logger.warning("p99_today 조회 실패 (floor=%d 사용): %s", SCORE_FLOOR_MIN, exc)
        return 0.0


def fetch_candidates(es: Elasticsearch, since_minutes: int) -> list[dict[str, Any]]:
    """최근 since_minutes 동안 적재된 risk doc 중 total_score >= SCORE_FLOOR_MIN.

    floor 미만은 어차피 gate 가 거르므로 ES 쿼리에서 1차 필터링한다.
    """
    gte = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
    try:
        resp = es.search(
            index=RISK_INDEX, size=200,
            query={"bool": {"filter": [
                {"range": {"computed_at": {"gte": gte}}},
                {"range": {"total_score": {"gte": SCORE_FLOOR_MIN}}},
            ]}},
            sort=[{"total_score": {"order": "desc"}}],
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("uba-risk-scores 조회 실패: %s", exc)
        return []
    return [h["_source"] for h in resp.get("hits", {}).get("hits", [])]


async def run_once(since_minutes: int) -> int:
    """폴링 1사이클 — 후보 risk doc 을 Phase 3a 로 넘긴다. 발행 알람 수 반환."""
    es = _es()
    try:
        p99 = fetch_p99_today(es)
        candidates = fetch_candidates(es, since_minutes)
    finally:
        es.close()

    logger.info("후보 risk doc %d건 (최근 %d분, p99_today=%.0f)",
                len(candidates), since_minutes, p99)
    if not candidates:
        return 0

    sent = 0
    async with ReActOrchestrator() as orch:
        for risk_doc in candidates:
            tid = f"{risk_doc.get('target_type')}:{risk_doc.get('target_id')}"
            try:
                result = await orch.run_phase_3a(risk_doc, p99_today=p99)
            except Exception as exc:  # noqa: BLE001 — 한 건 실패가 폴링을 멈추면 안 됨
                logger.error("run_phase_3a 실패 (%s): %s", tid, exc)
                continue
            if result is not None:
                sent += 1
                logger.info("Phase 3a 알람 발행: %s score=%s dominant=%s",
                            tid, risk_doc.get("total_score"),
                            risk_doc.get("dominant_factor"))
    logger.info("사이클 완료 — %d/%d 건 LLM 분석·알람", sent, len(candidates))
    return sent


async def _main() -> int:
    p = argparse.ArgumentParser(description="ZETI UBA Phase 3a 폴러")
    p.add_argument("--since", type=int, default=10, help="risk doc 조회 윈도우 (분)")
    p.add_argument("--loop", type=int, default=0, help="반복 간격(초). 0이면 1회만.")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    if args.loop <= 0:
        await run_once(args.since)
        return 0

    logger.info("상시 폴링 시작 — %d초 간격", args.loop)
    while True:
        try:
            await run_once(args.since)
        except Exception as exc:  # noqa: BLE001 — 사이클 실패해도 폴러는 계속
            logger.error("폴링 사이클 실패: %s", exc)
        await asyncio.sleep(args.loop)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
