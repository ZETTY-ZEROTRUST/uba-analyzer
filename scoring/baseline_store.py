"""
baseline_store.py — Phase 2: 통계 팩터의 "평소 분포" 산출

event/ip aggregator 출력에서 metric별 분포(mean/std/p50/p95/p99)를 뽑아
uba-baseline 인덱스에 저장한다. factor_engine 의 z-score 계산 입력.

설계 의도:
  - request_burst / response_size_burst / ip_user_diversity / cumulative_exfil 은
    z-score 기반 통계 팩터다. z = (관측값 - mean) / std 이므로 "평소 분포"가
    없으면 채점이 불가능하다. 이 모듈이 그 분포를 만든다.
  - baseline 오염 방지 2겹:
    ① is_baseline_eligible=false (s7-cafe 검증 트래픽 등)는 제외.
    ② 직전 라운드 점수 70+ 타깃 제외 — 공격 트래픽이 "평소"에 섞이면 평균이
       부풀어 이후 공격이 정상으로 보인다.
  - sample_count 를 함께 저장 → factor_engine 이 cold start(sample<100) 분기.
  - ip_user_diversity 는 윈도우(5min/1h/24h)마다 분포가 다르므로 윈도우별 분리.
"""
import statistics
from datetime import datetime, UTC

MIN_SAMPLES = 100   # 이 미만이면 cold start — factor_engine 이 통계 팩터 0점 처리


def _percentile(sorted_vals, q):
    """정렬된 리스트의 q 분위수 (nearest-rank)."""
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, int(q * len(sorted_vals)))
    return round(float(sorted_vals[idx]), 3)


def _distribution(values):
    """숫자 리스트 → 분포 통계 dict."""
    n = len(values)
    if n == 0:
        return {"sample_count": 0, "mean": 0.0, "std": 0.0,
                "p50": 0.0, "p95": 0.0, "p99": 0.0}
    s = sorted(values)
    return {
        "sample_count": n,
        "mean": round(statistics.fmean(values), 3),
        "std": round(statistics.pstdev(values) if n > 1 else 0.0, 3),
        "p50": _percentile(s, 0.50),
        "p95": _percentile(s, 0.95),
        "p99": _percentile(s, 0.99),
    }


def _eligible(doc, excluded):
    """baseline 누적 적격 여부 — seed 부적격 또는 고위험 타깃은 제외."""
    if not doc.get("is_baseline_eligible", True):
        return False
    return doc.get("target_id") not in excluded


def compute_baseline(user_events, ip_events, asn_events=None, excluded_targets=None):
    """user/IP/ASN 집계 doc → metric별 분포 baseline doc 리스트.

    Args:
        user_events: event_aggregator.aggregate_user_events() 출력.
        ip_events: ip_aggregator.aggregate_ip_events() 출력.
        asn_events: ip_aggregator.aggregate_asn_events() 출력 (Route B). 없으면 [].
        excluded_targets: 직전 라운드 점수 70+ 타깃 id set (bootstrap 시 빈 set).

    Returns:
        list of dict — uba-baseline 색인용 doc (metric별 1건).
    """
    excluded = excluded_targets or set()
    now = datetime.now(UTC).isoformat()

    u_ok = [d for d in user_events if _eligible(d, excluded)]
    ip_ok = [d for d in ip_events if _eligible(d, excluded)]
    asn_ok = [d for d in (asn_events or []) if _eligible(d, excluded)]

    metrics = {
        # request_burst: user-윈도우 요청 수 분포
        "request_burst": [d["request_count"] for d in u_ok],
        # response_size_burst: user-윈도우 응답 바이트 합 분포
        "response_size_burst": [d["response_bytes_total"] for d in u_ok],
        # cumulative_exfil: IP 24h 윈도우 누적 응답 바이트 분포
        "cumulative_exfil": [d["response_bytes_total"]
                             for d in ip_ok if d["window_size"] == "24h"],
    }
    # ip_user_diversity: IP-윈도우 unique_subs — 윈도우별로 분포가 다르다.
    # asn_user_diversity: ASN-윈도우 unique_subs (Route B) — ASN 은 IP 보다 많은
    #   sub 를 보므로 IP 와 분포가 다르다 → 별도 metric 으로 분리한다.
    for win in ("5min", "1h", "24h"):
        metrics[f"ip_user_diversity_{win}"] = [
            d["unique_subs_count"] for d in ip_ok if d["window_size"] == win
        ]
        metrics[f"asn_user_diversity_{win}"] = [
            d["unique_subs_count"] for d in asn_ok if d["window_size"] == win
        ]

    docs = []
    for metric, values in metrics.items():
        dist = _distribution(values)
        dist["metric"] = metric
        dist["computed_at"] = now
        dist["cold_start"] = dist["sample_count"] < MIN_SAMPLES
        docs.append(dist)
    return docs


def index_baseline(baseline_docs):
    """baseline doc 리스트 → {metric: dist} dict. factor_engine 이 조회용으로 쓴다."""
    return {d["metric"]: d for d in baseline_docs}


# === 테스트 ===
if __name__ == "__main__":
    import random
    random.seed(42)

    # 정상 user 집계 200개 (request_count 평균 ~12)
    user_events = [
        {"target_id": f"u{i}", "window_size": "5min", "is_baseline_eligible": True,
         "request_count": max(1, int(random.gauss(12, 3))),
         "response_bytes_total": max(0, int(random.gauss(8000, 2000)))}
        for i in range(200)
    ]
    # 공격 user 1개 — 점수 70+ 로 가정, excluded 로 제외돼야
    user_events.append({"target_id": "attacker", "window_size": "5min",
                        "is_baseline_eligible": True, "request_count": 900,
                        "response_bytes_total": 5_000_000})
    # IP 24h 집계 150개
    ip_events = [
        {"target_id": f"ip{i}", "window_size": "24h", "is_baseline_eligible": True,
         "unique_subs_count": random.randint(1, 4),
         "response_bytes_total": max(0, int(random.gauss(40000, 12000)))}
        for i in range(150)
    ]

    # ASN 24h 집계 (Route B) — 정상 비-cgnat ASN 20개
    asn_events = [
        {"target_id": f"AS{1000 + i}", "window_size": "24h", "is_baseline_eligible": True,
         "unique_subs_count": random.randint(2, 8),
         "response_bytes_total": max(0, int(random.gauss(30000, 9000)))}
        for i in range(20)
    ]
    base = compute_baseline(user_events, ip_events, asn_events,
                            excluded_targets={"attacker"})
    idx = index_baseline(base)

    print("=== baseline 분포 ===")
    for m, d in idx.items():
        print(f"  {m:26} n={d['sample_count']:4} mean={d['mean']:>10} "
              f"std={d['std']:>9} p99={d['p99']:>10} cold_start={d['cold_start']}")

    rb = idx["request_burst"]
    assert rb["sample_count"] == 200, "공격 user 제외 → 200"
    assert rb["mean"] < 20, f"공격 제외로 평균 정상권 (got {rb['mean']})"
    assert idx["ip_user_diversity_24h"]["cold_start"] is False, "150 samples >= 100 → cold_start False"
    assert idx["ip_user_diversity_5min"]["sample_count"] == 0, "5min IP 집계 없음 → cold_start"
    assert idx["ip_user_diversity_5min"]["cold_start"] is True, "0 samples → cold_start True"
    assert idx["asn_user_diversity_24h"]["sample_count"] == 20, "ASN 24h baseline 20 samples"
    assert idx["asn_user_diversity_5min"]["sample_count"] == 0, "ASN 5min 집계 없음"
    print("\n계약 점검 통과 ✅ (공격 user baseline 제외 + cold_start + ASN baseline 분리)")
