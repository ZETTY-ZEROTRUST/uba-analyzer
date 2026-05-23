"""
es_writer.py — Phase 1/2: 집계·점수 doc 을 ES 일자별 인덱스에 bulk 저장

설계 의도:
  - uba-events / uba-risk-scores / uba-baseline 은 모두 "일자별 인덱스 + bulk insert"
    패턴이 동일하다. writer 를 하나로 통일해 중복을 없앤다 (alert_saver.py 의
    helpers.bulk 패턴 재사용).
  - 일자별 인덱스({prefix}-YYYY.MM.dd): ILM/롤오버를 단순하게 한다. doc 의 시간
    기준은 인덱스명이 아니라 doc 안의 window_start 필드 — Kibana 는 그걸로 쿼리하므로
    seed 가 72h 전 윈도우를 오늘 인덱스에 넣어도 시계열은 정확하다.
  - bulk 실패해도 예외를 위로 던지지 않는다 (raise_on_error=False) — 분석
    파이프라인이 ES 일시 장애로 통째 멈추지 않게.
"""
from datetime import datetime, UTC
from elasticsearch import Elasticsearch, helpers
from dotenv import load_dotenv
import os
import urllib3

load_dotenv()
urllib3.disable_warnings()

ES_HOST = os.environ["ES_HOST"]
ES_USER = os.environ["ES_USER"]
ES_PASS = os.environ["ES_PASS"]


def get_es_client():
    return Elasticsearch([ES_HOST], basic_auth=(ES_USER, ES_PASS), verify_certs=False)


def daily_index(prefix):
    """{prefix}-YYYY.MM.dd (UTC 기준 오늘)."""
    return f"{prefix}-{datetime.now(UTC).strftime('%Y.%m.%d')}"


def write_docs(docs, index_prefix, es=None):
    """docs 리스트를 {index_prefix}-{today} 인덱스에 bulk insert.

    Args:
        docs: 저장할 dict 리스트 (event_aggregator / factor_engine 출력 등).
        index_prefix: "uba-events" / "uba-risk-scores" / "uba-baseline".
        es: ES 클라이언트 (없으면 생성).

    Returns:
        {"saved": int, "failed": int, "index": str}
    """
    if es is None:
        es = get_es_client()
    index = daily_index(index_prefix)
    if not docs:
        return {"saved": 0, "failed": 0, "index": index}

    actions = [{"_index": index, "_source": d} for d in docs]
    saved, failed = 0, 0
    try:
        ok, errors = helpers.bulk(es, actions, raise_on_error=False, stats_only=False)
        saved = ok
        failed = len(errors) if isinstance(errors, list) else 0
        es.indices.refresh(index=index)
    except Exception as e:
        print(f"  [ERROR] ES bulk 저장 실패 ({index}): {e}")
        failed = len(actions)
    return {"saved": saved, "failed": failed, "index": index}


# === 테스트 (mock — ES 미연결) ===
if __name__ == "__main__":
    class _FakeIndices:
        def refresh(self, index):
            pass

    class _FakeES:
        indices = _FakeIndices()

    # helpers.bulk 를 mock 으로 치환
    helpers.bulk = lambda es, actions, **kw: (len(list(actions)), [])

    r = write_docs([{"a": 1}, {"a": 2}, {"a": 3}], "uba-events", es=_FakeES())
    print(f"3건 저장: {r}")
    assert r["saved"] == 3 and r["failed"] == 0
    assert r["index"].startswith("uba-events-")

    r2 = write_docs([], "uba-risk-scores", es=_FakeES())
    print(f"빈 리스트: {r2}")
    assert r2["saved"] == 0

    print("계약 점검 통과 ✅")
