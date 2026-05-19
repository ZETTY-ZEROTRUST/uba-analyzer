"""
pipeline.py — Phase 1+2 배치 실행기 (실 ES 대상)

UBA EC2(10.0.41.20)에서 도는 Phase 1+2 의 단일 진입점. ES filebeat-* 의 실
로그를 읽어 집계 → baseline → 채점까지 한 번에 돌리고 결과를 ES 에 기록한다.

흐름:
  log_fetcher.fetch_logs_in_range   (filebeat-* 실 로그)
    → event_aggregator + ip_aggregator   (user/IP 윈도우 집계)   → uba-events
    → baseline_store.compute_baseline     (통계 팩터 평소 분포)    → uba-baseline
    → risk_scorer.score_all               (7 팩터 채점 + 등급)     → uba-risk-scores

실행 (UBA EC2):
  cd /opt/zeti-uba && git pull
  python3 pipeline.py --hours 72              # seed baseline 부트스트랩 (1회)
  python3 pipeline.py --hours 1 --no-baseline # 운영 배치 (baseline 재사용)
"""
import argparse
import logging
from datetime import datetime, timedelta, UTC

import log_fetcher
import event_aggregator
import ip_aggregator
import baseline_store
import risk_scorer
import es_writer

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%H:%M:%S")
logging.getLogger("elasticsearch").setLevel(logging.WARNING)
log = logging.getLogger("uba-pipeline")

# log_fetcher.fetch_logs_in_range 가 helpers.scan 페이지네이션을 쓰므로 구간
# 전체를 소비한다 — 단일 search 의 max_result_window(10k) 한도 없음.
# None = 무제한 (168h seed 117k doc 전량 baseline 반영).
FETCH_LIMIT = None


def run(hours, write=True, rebuild_baseline=True):
    es = log_fetcher.get_es_client()
    end = datetime.now(UTC)
    start = end - timedelta(hours=hours)

    log.info(f"[1] filebeat-* 조회: 최근 {hours}h")
    logs = log_fetcher.fetch_logs_in_range(es, start, end, limit=FETCH_LIMIT)
    log.info(f"    {len(logs)}건 정규화")
    if not logs:
        log.warning("로그 0건 — 종료")
        return

    log.info("[2] 집계 (user / IP / ASN)")
    user_events = event_aggregator.aggregate_user_events(logs)
    ip_events = ip_aggregator.aggregate_ip_events(logs)
    asn_events = ip_aggregator.aggregate_asn_events(logs)   # Route B — 분산 enumeration
    log.info(f"    user {len(user_events)} / IP {len(ip_events)} / ASN {len(asn_events)}")

    log.info("[3] baseline 산출")
    baseline_docs = baseline_store.compute_baseline(user_events, ip_events, asn_events)
    baseline = baseline_store.index_baseline(baseline_docs)
    rb = baseline.get("request_burst", {})
    log.info(f"    request_burst: mean={rb.get('mean')} n={rb.get('sample_count')} "
             f"cold_start={rb.get('cold_start')}")

    log.info("[4] 7 팩터 채점")
    risk_docs = risk_scorer.score_all(user_events, ip_events, baseline, asn_events=asn_events)
    summary = risk_scorer.summarize(risk_docs)
    log.info(f"    {summary}")

    if write:
        log.info("[5] ES 기록")
        r1 = es_writer.write_docs(user_events + ip_events + asn_events, "uba-events", es)
        log.info(f"    uba-events: {r1['saved']} 저장 ({r1['index']})")
        if rebuild_baseline:
            r2 = es_writer.write_docs(baseline_docs, "uba-baseline", es)
            log.info(f"    uba-baseline: {r2['saved']} 저장 ({r2['index']})")
        r3 = risk_scorer.write_risk_scores(risk_docs, es)
        log.info(f"    uba-risk-scores: {r3['saved']} 저장 ({r3['index']})")
    else:
        log.info("[5] --dry-run — ES 기록 생략")

    log.info(f"완료 — 알람 후보 {summary['alert_count']}건 (max score {summary['max_score']})")
    return risk_docs


def main():
    p = argparse.ArgumentParser(description="ZETI UBA Phase 1+2 배치")
    p.add_argument("--hours", type=int, default=72, help="조회 윈도우 (default 72h)")
    p.add_argument("--dry-run", action="store_true", help="ES 기록 생략")
    p.add_argument("--no-baseline", action="store_true",
                   help="baseline 재계산만 하고 uba-baseline 기록은 생략")
    args = p.parse_args()
    try:
        es = log_fetcher.get_es_client()
        info = es.info()
        log.info(f"ES 연결 OK ({info['version']['number']})")
    except Exception as e:
        log.error(f"ES 연결 실패: {e}")
        raise SystemExit(1)
    run(args.hours, write=not args.dry_run, rebuild_baseline=not args.no_baseline)


if __name__ == "__main__":
    main()
