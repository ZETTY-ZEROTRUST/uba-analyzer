#!/usr/bin/env python3
"""
build_3b_bundle.py — Phase 3b orchestrator 입력 bundle 생성.

phase_3b.build_user_prompt 시그니처(6 인자)에 그대로 박을 수 있는 JSON 을
uba-alerts-* + uba-risk-scores-* 에서 fetch 해 만든다.

사용:
    python scripts/build_3b_bundle.py --hours 24 --output /tmp/3b_bundle.json
    python llm-agent/orchestrator.py --phase 3b --input /tmp/3b_bundle.json

bundle JSON 키:
    report_type / time_range_start / time_range_end
    alerts (Phase 3a 결과)              ← uba-alerts-* size 50
    score_timeseries (1h buckets)       ← uba-risk-scores-* date_histogram
    sub_threshold_activity (30~50 doc)  ← uba-risk-scores-* range filter
"""
import os, sys, json, argparse
from pathlib import Path
from datetime import datetime, timedelta, UTC

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_ROOT / ".env")

ALERT_THRESHOLD = 50           # scoring/risk_scorer.py 와 동일
SUB_THRESHOLD_LOW = 30         # 약한 신호 하한 (캠페인 timeline 정황)
ALERTS_INDEX = "uba-alerts-*"
RISK_INDEX = "uba-risk-scores-*"


def get_es() -> Elasticsearch:
    url = os.environ.get("ES_URL", "https://10.0.41.10:9200")
    user = os.environ["ES_USER"]
    pw = os.environ["ES_PASS"]
    verify = os.environ.get("ES_SSL_VERIFY", "false").lower() == "true"
    return Elasticsearch(url, basic_auth=(user, pw), verify_certs=verify, request_timeout=30)


def fetch_alerts(es: Elasticsearch, gte: str, lte: str, size: int = 50) -> list[dict]:
    resp = es.search(
        index=ALERTS_INDEX,
        size=size,
        query={"range": {"@timestamp": {"gte": gte, "lte": lte}}},
        sort=[{"total_score": {"order": "desc"}}],
        ignore_unavailable=True,
    )
    return [h["_source"] for h in resp["hits"]["hits"]]


def fetch_score_timeseries(es: Elasticsearch, gte: str, lte: str) -> list[dict]:
    """1h 버킷 × max(total_score) — Phase 3b 가 캠페인 추이 보는 용도."""
    resp = es.search(
        index=RISK_INDEX,
        size=0,
        query={
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": gte, "lte": lte}}},
                    {"range": {"total_score": {"gte": 1}}},  # 0점 doc 노이즈 제외
                ]
            }
        },
        aggs={
            "buckets": {
                "date_histogram": {"field": "@timestamp", "fixed_interval": "1h"},
                "aggs": {"max_score": {"max": {"field": "total_score"}}},
            }
        },
        ignore_unavailable=True,
    )
    return [
        {"timestamp": b["key_as_string"], "max_score": b["max_score"]["value"], "doc_count": b["doc_count"]}
        for b in resp["aggregations"]["buckets"]["buckets"]
        if b["doc_count"] > 0
    ]


def fetch_sub_threshold(es: Elasticsearch, gte: str, lte: str, size: int = 20) -> list[dict]:
    """30 ≤ score < 50 — 알람은 안 떴지만 약한 정황으로 캠페인 timeline 에 엮을 신호."""
    resp = es.search(
        index=RISK_INDEX,
        size=size,
        query={
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": gte, "lte": lte}}},
                    {"range": {"total_score": {"gte": SUB_THRESHOLD_LOW, "lt": ALERT_THRESHOLD}}},
                ]
            }
        },
        sort=[{"total_score": {"order": "desc"}}],
        ignore_unavailable=True,
    )
    return [h["_source"] for h in resp["hits"]["hits"]]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--report-type", choices=["hourly", "daily"], default="daily")
    p.add_argument("--output", default=None, help="기본 stdout")
    args = p.parse_args()

    end = datetime.now(UTC)
    start = end - timedelta(hours=args.hours)
    gte = start.isoformat()
    lte = end.isoformat()

    es = get_es()
    bundle = {
        "report_type": args.report_type,
        "time_range_start": gte,
        "time_range_end": lte,
        "alerts": fetch_alerts(es, gte, lte),
        "score_timeseries": fetch_score_timeseries(es, gte, lte),
        "sub_threshold_activity": fetch_sub_threshold(es, gte, lte),
    }

    text = json.dumps(bundle, ensure_ascii=False, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(
            f"✅ {args.output} "
            f"(alerts={len(bundle['alerts'])} "
            f"buckets={len(bundle['score_timeseries'])} "
            f"weak={len(bundle['sub_threshold_activity'])})",
            file=sys.stderr,
        )
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
