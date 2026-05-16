"""
integration_test.py — Phase 1+2 로컬 통합 테스트 (synthetic end-to-end)

seed 정상 트래픽 + S2/S4/S6 공격 주입 → 전 파이프라인을 통과시켜 v12 팩터
발동 매트릭스를 검증한다. ES 없이 (synthetic) 로직 전체를 확인하는 게이트.

파이프라인:
  seed-baseline.make_doc / attack inject
    → log_fetcher.normalize_log
    → event_aggregator + ip_aggregator
    → baseline_store.compute_baseline   (공격 doc 은 baseline_eligible=False 라 제외)
    → risk_scorer.score_all             (factor_engine + attacker_level_classifier)

검증 매트릭스 (v12):
  정상 user/IP → score 0, L0
  S2 하이재킹  → user doc, dominant token_replay, L2
  S4 enumeration → IP doc(5min), dominant ip_user_diversity, L4
  S6 Slow & Low → IP doc(24h), dominant ip_user_diversity, L4(Slow & Low)
"""
import importlib.util
import uuid
from datetime import datetime, timedelta, timezone

# seed-baseline.py 로드 (log-pipeline 레포)
_spec = importlib.util.spec_from_file_location(
    "seed_baseline", "../log-pipeline/scripts/seed-baseline.py")
sb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sb)

import log_fetcher
import event_aggregator
import ip_aggregator
import baseline_store
import risk_scorer

NOW = datetime.now(timezone.utc)


def attack_doc(ts, sub, jti, iat, client_ip, ip_class, ip_country, uri,
               bytes_sent=2000, status=200):
    """filebeat-* doc 형태의 공격 주입 doc (baseline_eligible=False)."""
    return {
        "@timestamp": ts.isoformat().replace("+00:00", "Z"),
        "ip": "10.0.1.109", "client_ip": client_ip,
        "ip_class": ip_class, "ip_country": ip_country,
        "ip_asn": "AS16509" if ip_class == "cloud" else "AS4766",
        "ip_org": "AWS" if ip_class == "cloud" else "KT",
        "is_nat_whitelisted": ip_class == "cgnat_kr",
        "user_agent": "python-requests/2.31",
        "method": "GET", "uri": uri, "status": str(status),
        "bytes_sent": str(bytes_sent), "response_time": "0.05",
        "jwt": {
            "alg": "ES256", "kid": "alias/jwt-signing-key-external", "typ": "JWT",
            "sub": sub, "jti": jti, "iat": iat, "exp": iat + 600,
            "auth_time": iat, "nbf": iat, "iss": "https://auth.zeti.com/",
            "aud": ["https://api.zeti.com"], "client_id": "zeti-web",
            "scp": ["openid", "core"], "acr": "aal1", "amr": ["pwd"],
            "ext": {"LSID": f"lsid-{sub}", "fiat": iat, "v": 2},
        },
        "zeti_seed": {"source": "attack_inject", "scenario": "attack",
                      "baseline_eligible": False},
    }


def build_dataset():
    """seed 정상 + S2/S4/S6 공격 raw doc 리스트."""
    start = NOW - timedelta(hours=72)
    docs = sb.build_scenario_docs("normal", 72, 8640, start)

    # 윈도우 경계 정렬된 최근 5분 윈도우 (S2/S4 용)
    win5 = (int(NOW.timestamp()) // 300) * 300 - 600
    # 24h 윈도우 경계 (S6 용)
    win24 = (int(NOW.timestamp()) // 86400) * 86400

    def ts(epoch):
        return datetime.fromtimestamp(epoch, timezone.utc)

    # ── S2 하이재킹: victim 진짜 토큰(jti 1개)이 victim IP(KT) + attacker IP(cloud)에서 ──
    s2_jti, s2_iat = str(uuid.uuid4()), win5
    for i in range(5):   # victim 정상 활동 (cgnat_kr / KR)
        docs.append(attack_doc(ts(win5 + i * 10), "140000007", s2_jti, s2_iat,
                               "118.235.82.230", "cgnat_kr", "KR", "/api/users/me", 150))
    for i in range(5):   # attacker 가 같은 토큰 탈취 사용 (cloud / US)
        docs.append(attack_doc(ts(win5 + 60 + i * 10), "140000007", s2_jti, s2_iat,
                               "13.124.0.9", "cloud", "US", "/api/orders/140000007", 1800))

    # ── S4 enumeration: 단일 cloud IP 가 5분 내 100명 sub 의 /addresses 조회 ──
    for i in range(100):
        sub = f"1400{20000 + i}"
        docs.append(attack_doc(ts(win5 + (i % 280)), sub, str(uuid.uuid4()), win5,
                               "203.0.113.50", "cloud", "US",
                               f"/api/addresses/{sub}", 2400))

    # ── S6 Slow & Low: 단일 IP 가 24h 에 걸쳐 40명 sub — 5분엔 안 보이고 24h 윈도우만 ──
    for i in range(40):
        sub = f"1400{30000 + i}"
        docs.append(attack_doc(ts(win24 + i * 2150), sub, str(uuid.uuid4()), win24 + i * 2150,
                               "198.51.100.9", "unknown", "US",
                               f"/api/addresses/{sub}", 3000))
    return docs


def run():
    raw = build_dataset()
    logs = [log_fetcher.normalize_log(d) for d in raw]
    user_events = event_aggregator.aggregate_user_events(logs)
    ip_events = ip_aggregator.aggregate_ip_events(logs)
    baseline = baseline_store.index_baseline(
        baseline_store.compute_baseline(user_events, ip_events))
    risk_docs = risk_scorer.score_all(user_events, ip_events, baseline)

    print(f"raw {len(raw)} → normalize {len(logs)} → "
          f"user집계 {len(user_events)} / IP집계 {len(ip_events)} → risk doc {len(risk_docs)}")
    print(f"baseline request_burst: mean={baseline['request_burst']['mean']} "
          f"n={baseline['request_burst']['sample_count']}")
    print()

    by_id = {}
    for d in risk_docs:
        by_id.setdefault(d["target_id"], []).append(d)

    def best(tid):
        """그 타깃의 최고 점수 risk doc."""
        return max(by_id.get(tid, []), key=lambda d: d["total_score"], default=None)

    print("=== v12 팩터 매트릭스 검증 ===")
    checks = []

    # S2 — victim user 140000007
    s2 = best("140000007")
    checks.append(("S2 하이재킹 (user)", s2,
                   s2 and s2["total_score"] == 80 and s2["dominant_factor"] == "token_replay"
                   and s2["attacker_level"] == "L2"))

    # S4 — attacker IP 203.0.113.50, 5min 윈도우
    s4_docs = [d for d in by_id.get("203.0.113.50", []) if d["window_size"] == "5min"]
    s4 = max(s4_docs, key=lambda d: d["total_score"], default=None)
    checks.append(("S4 enumeration (IP 5min)", s4,
                   s4 and s4["dominant_factor"] == "ip_user_diversity"
                   and s4["attacker_level"] == "L4" and s4["total_score"] >= 50))

    # S6 — attacker IP 198.51.100.9, 24h 윈도우
    s6_docs = [d for d in by_id.get("198.51.100.9", []) if d["window_size"] == "24h"]
    s6 = max(s6_docs, key=lambda d: d["total_score"], default=None)
    checks.append(("S6 Slow & Low (IP 24h)", s6,
                   s6 and s6["dominant_factor"] == "ip_user_diversity"
                   and s6["attacker_level"] == "L4(Slow & Low)" and s6["total_score"] >= 50))

    # S6 — 같은 IP 의 5min 윈도우는 조용해야 (저속이라 5분엔 안 보임)
    s6_5min = [d for d in by_id.get("198.51.100.9", []) if d["window_size"] == "5min"]
    s6_quiet = all(d["total_score"] == 0 for d in s6_5min)
    checks.append(("S6 5min 윈도우는 조용 (다중윈도우 효과)", f"{len(s6_5min)}개 윈도우", s6_quiet))

    # 정상 — seed user 140000511 은 알람 없어야
    normal_docs = by_id.get("140000511", [])
    normal_ok = all(d["total_score"] < 50 for d in normal_docs)
    checks.append(("정상 seed user 140000511 무알람", f"{len(normal_docs)}개 윈도우", normal_ok))

    for name, doc, ok in checks:
        mark = "PASS" if ok else "FAIL"
        if isinstance(doc, dict):
            detail = (f"score={doc['total_score']} dominant={doc['dominant_factor']} "
                      f"level={doc['attacker_level']}")
        else:
            detail = str(doc)
        print(f"  [{mark}] {name:38} {detail}")

    print(f"\n전체 요약: {risk_scorer.summarize(risk_docs)}")

    failed = [c[0] for c in checks if not c[2]]
    if failed:
        print(f"\n❌ 실패: {failed}")
        raise SystemExit(1)
    print("\n✅ Phase 1+2 통합 테스트 전체 통과 — v12 팩터 매트릭스 정합")


if __name__ == "__main__":
    run()
