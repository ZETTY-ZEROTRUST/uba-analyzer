"""
risk_scorer.py — Phase 2: 위험 점수 산출 오케스트레이터 + uba-risk-scores writer

event/ip aggregator 출력 + baseline 을 받아 factor_engine 으로 채점하고
attacker_level_classifier 로 등급·유출 플래그를 붙여, uba-risk-scores 색인용
완성 risk doc 리스트를 만든다.

설계 의도:
  - Phase 2 의 마지막 조립 단계 — 흩어진 채점 모듈(factor_engine /
    attacker_level_classifier)을 하나의 흐름으로 묶고, 저장은 공통 es_writer 재사용.
  - user-윈도우와 IP-윈도우를 모두 채점해 uba-risk-scores 에 함께 넣는다
    (target_type 으로 구분 — S2는 user doc, S4/S6는 IP doc 에서 알람이 뜬다).
  - pii_signals(backend AOP PII 카운트)는 연동 전이라 None — response_sensitivity
    는 0 으로 graceful degrade.
"""
import factor_engine
import attacker_level_classifier as alc
from es_writer import write_docs

ALERT_THRESHOLD = 50   # PROGRESS: 상위 위험 = score >= max(p99_today, 50)


def score_all(user_events, ip_events, baseline, pii_signals=None):
    """집계 doc → 완성 risk doc 리스트 (uba-risk-scores 색인용).

    Args:
        user_events: event_aggregator.aggregate_user_events() 출력.
        ip_events: ip_aggregator.aggregate_ip_events() 출력.
        baseline: baseline_store.index_baseline() 출력 ({metric: dist}).
        pii_signals: {user_id: pii_signal_dict} — backend AOP 연동 시. 없으면 None.

    Returns:
        list of dict — attacker_level / data_exfiltration_detected 까지 채워진 risk doc.
    """
    pii_signals = pii_signals or {}
    docs = []
    for ue in user_events:
        rd = factor_engine.score_user_window(ue, baseline, pii_signals.get(ue["target_id"]))
        alc.classify(rd)
        docs.append(rd)
    for ie in ip_events:
        rd = factor_engine.score_ip_window(ie, baseline)
        alc.classify(rd)
        docs.append(rd)
    return docs


def write_risk_scores(risk_docs, es=None):
    """risk doc 리스트 → uba-risk-scores-{date} bulk insert."""
    return write_docs(risk_docs, "uba-risk-scores", es=es)


def summarize(risk_docs):
    """채점 결과 요약 — alert 후보 / dominant 분포."""
    alerts = [d for d in risk_docs if d["total_score"] >= ALERT_THRESHOLD]
    dom = {}
    for d in alerts:
        k = d.get("dominant_factor") or "none"
        dom[k] = dom.get(k, 0) + 1
    return {
        "total_docs": len(risk_docs),
        "alert_count": len(alerts),
        "max_score": max((d["total_score"] for d in risk_docs), default=0),
        "dominant_breakdown": dom,
        "exfil_flagged": sum(1 for d in risk_docs if d.get("data_exfiltration_detected")),
    }


# === 테스트 ===
if __name__ == "__main__":
    baseline = {
        "request_burst": {"mean": 8.8, "std": 6.3, "sample_count": 979, "cold_start": False},
        "response_size_burst": {"mean": 9000.0, "std": 2500.0, "sample_count": 979, "cold_start": False},
        "cumulative_exfil": {"mean": 40000.0, "std": 12000.0, "sample_count": 150, "cold_start": False},
        "ip_user_diversity_5min": {"sample_count": 32, "cold_start": True},
        "ip_user_diversity_24h": {"sample_count": 32, "cold_start": True},
    }
    clean_trm = {"jti_count_with_class_crossing": 0, "jti_count_with_country_crossing": 0}
    clean_tv = {"score": 0, "triggered_rules": [], "violating_samples": []}

    user_events = [
        # 정상 user
        {"target_id": "140000511", "window_start": "t1", "window_size": "5min",
         "request_count": 12, "response_bytes_total": 9000,
         "token_replay_meta": clean_trm, "token_violation": clean_tv},
        # S2 하이재킹 — jti ip_class 교차
        {"target_id": "140000007", "window_start": "t2", "window_size": "5min",
         "request_count": 8, "response_bytes_total": 4000,
         "token_replay_meta": {"jti_count_with_class_crossing": 1,
                               "jti_count_with_country_crossing": 1, "violating_samples": []},
         "token_violation": clean_tv},
    ]
    ip_events = [
        # 정상 IP
        {"target_id":"118.235.82.230", "window_start": "t1", "window_size": "5min",
         "unique_subs_count":1, "response_bytes_total": 9000, "ip_class": "cgnat_kr",
         "ip_asn": "AS4766", "ip_org": "KT", "ip_country": "KR", "is_nat_whitelisted": True},
        # S4 enumeration — cloud IP, 100 sub
        {"target_id":"13.124.0.9", "window_start": "t2", "window_size": "5min",
         "unique_subs_count":100, "response_bytes_total": 250000, "ip_class": "cloud",
         "ip_asn": "AS16509", "ip_org": "AWS", "ip_country": "US", "is_nat_whitelisted": False},
        # S6 Slow & Low — 24h 윈도우, 다수 sub
        {"target_id":"203.0.113.7", "window_start": "t3", "window_size": "24h",
         "unique_subs_count":40, "response_bytes_total": 900000, "ip_class": "unknown",
         "ip_asn": "AS-X", "ip_org": "?", "ip_country": "US", "is_nat_whitelisted": False},
    ]

    docs = score_all(user_events, ip_events, baseline)
    print("=== risk doc 채점 결과 ===")
    for d in docs:
        print(f"  [{d['target_type']:4} {d['target_id']:16}] score={d['total_score']:3} "
              f"dominant={str(d['dominant_factor']):20} level={d['attacker_level']}")

    print(f"\n요약: {summarize(docs)}")

    by_id = {d["target_id"]: d for d in docs}
    assert by_id["140000511"]["total_score"] == 0 and by_id["140000511"]["attacker_level"] == "L0"
    assert by_id["140000007"]["total_score"] == 80 and by_id["140000007"]["attacker_level"] == "L2"
    assert by_id["13.124.0.9"]["dominant_factor"] == "ip_user_diversity"
    assert by_id["13.124.0.9"]["attacker_level"] == "L4"
    assert by_id["203.0.113.7"]["attacker_level"] == "L4(Slow & Low)"
    print("\n계약 점검 통과 ✅ (정상 L0 / S2 L2 / S4 L4 / S6 L4 Slow&Low)")
