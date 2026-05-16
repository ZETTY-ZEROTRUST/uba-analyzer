"""
event_aggregator.py — Phase 1: 정규화 로그 → user별 5분 윈도우 집계

log_fetcher.normalize_log() 출력 리스트를 (user_id, 5분 윈도우) 단위로 묶어
Phase 2 팩터 엔진이 소비할 집계 지표 doc 을 만든다. (uba-events 인덱스 입력)

설계 의도:
  - 5분 윈도우 = request_burst 의 평가 단위. 멘토 4단계 중 "즉각 공격"(S4) 포착 해상도.
  - status 2xx 와 4xx/5xx 를 분리 카운트한다. 실패 요청은 정상 행위 분포가 아니므로
    baseline 오염을 막으려면 success/error 를 섞으면 안 된다.
  - v12 token_replay 증거를 이 단계에서 미리 만든다 — 윈도우 안의 jti 가
    ip_class / ip_country 경계를 교차했는지 모아둔다. factor_engine 은 점수만 매긴다.
    (집계=사실 수집 / 채점=factor_engine — 책임 분리)
  - seed provenance(baseline_eligible)를 윈도우로 전파해 baseline_store 가
    s7-cafe 같은 검증용 트래픽을 baseline 누적에서 뺄 수 있게 한다.
"""
import re
from collections import defaultdict
from datetime import datetime, timezone

from token_violation import compute_token_violation

WINDOW_SECONDS = 300   # 5분

# userId 를 path param 으로 받는 민감 endpoint — IDOR/enumeration 의 표적.
# 예: /api/addresses/140000511 , /api/orders/140000512
SENSITIVE_URI_RE = re.compile(r"/(addresses|orders)/\d+")


def window_start_epoch(receive_epoch):
    """epoch seconds → 5분 윈도우 시작 epoch."""
    return (receive_epoch // WINDOW_SECONDS) * WINDOW_SECONDS


def _epoch_to_iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def aggregate_user_events(logs):
    """정규화 로그 리스트 → user-윈도우 집계 doc 리스트.

    Args:
        logs: log_fetcher.normalize_log() 출력 리스트.

    Returns:
        list of dict — uba-events 색인용 user 집계 doc.
    """
    buckets = defaultdict(list)
    for g in logs:
        uid = g.get("user_id")
        ep = g.get("receive_epoch")
        if uid is None or ep is None:
            continue   # JWT 없는 로그(ALB 헬스체크 등)는 user 집계 대상 아님
        buckets[(uid, window_start_epoch(ep))].append(g)

    return [_build_user_doc(uid, win, grp) for (uid, win), grp in buckets.items()]


def _build_token_replay_meta(group):
    """윈도우 내 jti → {ip, ip_class, ip_country} 집합을 모아 v12 token_replay 증거 생성.

    v12: token_replay 는 jti 가 ip_class / ip_country 경계를 교차했는지로 판정한다.
    같은 jti 가 단일 ip_class 안에서만 보이면 정상 (CGNAT 모바일 IP 로테이션).
    """
    jti_ips = defaultdict(set)
    jti_classes = defaultdict(set)
    jti_countries = defaultdict(set)
    for g in group:
        jti = g.get("jwt_id")
        if not jti:
            continue
        if g.get("client_ip"):
            jti_ips[jti].add(g["client_ip"])
        if g.get("ip_class"):
            jti_classes[jti].add(g["ip_class"])
        if g.get("ip_country"):
            jti_countries[jti].add(g["ip_country"])

    class_crossing = 0
    country_crossing = 0
    samples = []
    for jti in jti_ips:
        classes = jti_classes.get(jti, set())
        countries = jti_countries.get(jti, set())
        crossed_class = len(classes) > 1
        crossed_country = len(countries) > 1
        if crossed_class:
            class_crossing += 1
        if crossed_country:
            country_crossing += 1
        if crossed_class or crossed_country:
            samples.append({
                "jti": jti,
                "ip_set": sorted(jti_ips[jti]),
                "ip_class_set": sorted(classes),
                "ip_country_set": sorted(countries),
                "crossing_type": "ip_class" if crossed_class else "ip_country",
            })

    return {
        "jti_count_with_class_crossing": class_crossing,
        "jti_count_with_country_crossing": country_crossing,
        "violating_samples": samples,
    }


def _build_user_doc(user_id, window_start, group):
    """한 (user, 윈도우) 버킷 → 집계 doc."""
    request_count = len(group)
    error_count = sum(1 for g in group if g["status"] >= 400)
    success_count = sum(1 for g in group if 200 <= g["status"] < 300)
    suspicious = sum(1 for g in group if SENSITIVE_URI_RE.search(g.get("uri") or ""))

    ip_set = sorted({g["client_ip"] for g in group if g.get("client_ip")})
    jti_set = sorted({g["jwt_id"] for g in group if g.get("jwt_id")})
    alg_set = sorted({g["alg"] for g in group if g.get("alg")})
    kid_set = sorted({g["kid"] for g in group if g.get("kid")})

    bytes_list = [g["bytes_sent"] for g in group]
    resp_total = sum(bytes_list)

    window_iso = _epoch_to_iso(window_start)
    return {
        # uba-events 매핑은 dynamic:strict — 필드명이 스키마와 정확히 일치해야 한다.
        # 타깃 식별은 target_type + target_id 일반 키 (user/ip 공통).
        "@timestamp": window_iso,
        "target_type": "user",
        "target_id": user_id,
        "window_start": window_iso,
        "window_size": "5min",

        "request_count": request_count,
        "success_count": success_count,
        "error_count": error_count,
        "error_rate": round(error_count / request_count, 4) if request_count else 0.0,
        "unique_uris_count": len({g.get("uri") for g in group}),
        "suspicious_uri_count": suspicious,

        "ip_set": ip_set,
        "ip_count": len(ip_set),
        "jti_set": jti_set,
        "jti_count": len(jti_set),
        "alg_set": alg_set,
        "kid_set": kid_set,

        "response_bytes_total": resp_total,
        "response_bytes_avg": round(resp_total / request_count, 1) if request_count else 0.0,
        "response_bytes_max": max(bytes_list) if bytes_list else 0,

        "token_replay_meta": _build_token_replay_meta(group),
        # token_violation 결정론 룰을 집계 단계에서 미리 산출 (factor_engine 은 점수만 읽음)
        "token_violation": compute_token_violation(group),

        # 윈도우 내 로그가 모두 baseline 적격일 때만 윈도우 적격
        "is_baseline_eligible": all(g.get("baseline_eligible", True) for g in group),
    }


# === 테스트 ===
if __name__ == "__main__":
    # 합성 로그 — user A 정상 8건 + user B 의 jti 가 ip_class 교차 (하이재킹)
    base = {"status": 200, "uri": "/api/products", "bytes_sent": 2000,
            "ip_country": "KR", "alg": "ES256", "kid": "alias/jwt-signing-key-external"}
    logs = []
    for i in range(8):
        logs.append({**base, "user_id": "A", "receive_epoch": 1778000000 + i * 10,
                     "client_ip": "211.234.105.42", "ip_class": "cgnat_kr",
                     "jwt_id": "jti-A", "baseline_eligible": True})
    # user B: 같은 jti 가 cgnat_kr + cloud 에서 — 하이재킹
    logs.append({**base, "user_id": "B", "receive_epoch": 1778000005,
                 "client_ip": "1.2.3.4", "ip_class": "cgnat_kr", "jwt_id": "jti-B",
                 "ip_country": "KR", "baseline_eligible": True})
    logs.append({**base, "user_id": "B", "receive_epoch": 1778000020,
                 "client_ip": "13.124.0.9", "ip_class": "cloud", "jwt_id": "jti-B",
                 "ip_country": "US", "baseline_eligible": True})

    docs = aggregate_user_events(logs)
    print(f"=== 집계 doc {len(docs)}개 ===")
    for d in docs:
        print(f"\n[user {d['target_id']}] win={d['window_start']} req={d['request_count']} "
              f"jti={d['jti_count']} ip={d['ip_count']}")
        trm = d["token_replay_meta"]
        print(f"  token_replay: class_crossing={trm['jti_count_with_class_crossing']} "
              f"country_crossing={trm['jti_count_with_country_crossing']}")
        for s in trm["violating_samples"]:
            print(f"  교차 샘플: jti={s['jti']} class={s['ip_class_set']} "
                  f"country={s['ip_country_set']} type={s['crossing_type']}")

    a = next(d for d in docs if d["target_id"] == "A")
    b = next(d for d in docs if d["target_id"] == "B")
    assert a["token_replay_meta"]["jti_count_with_class_crossing"] == 0, "A 정상=교차 0"
    assert b["token_replay_meta"]["jti_count_with_class_crossing"] == 1, "B 하이재킹=교차 1"
    assert b["token_replay_meta"]["violating_samples"][0]["crossing_type"] == "ip_class"
    print("\n계약 점검 통과 ✅")
