"""
factor_engine.py — Phase 2: 7 팩터 산출 + 최종 위험 점수

event/ip aggregator 출력 + baseline 을 받아 7 팩터를 채점하고 하나의 최종
위험 점수로 합성한다. 출력은 uba-risk-scores 색인용 risk doc.

설계 의도:
  - 7 팩터를 3종으로 나눠 채점한다:
      · 결정론 (token_violation / token_replay): 룰 매칭 즉시 점수, baseline 불필요.
      · 통계   (request_burst / response_size_burst / cumulative_exfil): baseline
        z-score. sample_count<100(cold start)이면 0점 — 빈약한 분포로 허위 z 안 냄.
      · Override (ip_user_diversity / response_sensitivity): 발동 시 즉시 100.
  - 타깃 분리: 각 신호의 자연스러운 관측 단위로 채점한다.
      · user-윈도우  → token_violation / request_burst / token_replay / response_size_burst
        (S2 하이재킹은 victim user 의 jti 신호)
      · IP-윈도우    → ip_user_diversity / cumulative_exfil
        (S4 enumeration / S6 Slow&Low 는 단일 IP 신호)
  - 최종 점수 = min(100, max(override들, 결정론 + 0.3×통계합)).
    통계 팩터에 0.3 가중 — 통계는 보조 신호, 결정론/override 가 본 신호.
  - dominant_factor = 최종 점수에 가장 크게 기여한 팩터 (영문 키 저장, UI 는 한국어 변환).
"""
from datetime import datetime, UTC

# 7 팩터 영문 키 — uba-risk-scores.factor_breakdown 과 1:1
FACTOR_KEYS = [
    "token_violation", "request_burst", "token_replay", "response_size_burst",
    "ip_user_diversity", "response_sensitivity", "cumulative_exfil",
]

# UI(Slack/Kibana) 한국어 라벨 — 코드/ES 는 영문 키, 표시만 한국어
FACTOR_KR = {
    "token_violation": "토큰규격위반", "request_burst": "요청수급증",
    "token_replay": "토큰재현(Replay)", "response_size_burst": "응답크기급증",
    "ip_user_diversity": "IP-사용자다양성", "response_sensitivity": "응답민감도",
    "cumulative_exfil": "누적유출량",
}

IP_USER_DIVERSITY_WHITELIST = {"cgnat_kr"}   # soft cap 적용 ip_class
IP_USER_DIVERSITY_SOFT_CAP = 30


# ────────────────────────────────────────────────────────────────────────────
# 개별 팩터
# ────────────────────────────────────────────────────────────────────────────
def _zscore(value, dist):
    """baseline 분포 대비 z-score. cold start / std=0 이면 None."""
    if not dist or dist.get("cold_start") or not dist.get("std"):
        return None
    return (value - dist["mean"]) / dist["std"]


def factor_request_burst(request_count, baseline):
    """요청수급증 (통계, cap 25) — max(0, z-2)*5."""
    z = _zscore(request_count, baseline.get("request_burst"))
    if z is None:
        return 0    # cold start → 통계 팩터 0점
    return min(25, round(max(0.0, z - 2) * 5))


def factor_response_size_burst(bytes_total, baseline):
    """응답크기급증 (통계, cap 30) — max(0, z-2)*6. 응답 크기는 서버가 결정."""
    z = _zscore(bytes_total, baseline.get("response_size_burst"))
    if z is None:
        return 0
    return min(30, round(max(0.0, z - 2) * 6))


def factor_cumulative_exfil(cum_bytes, baseline):
    """누적유출량 (통계, cap 50) — max(0, z-2)*10. 3일 EMA 대비 누적 바이트."""
    z = _zscore(cum_bytes, baseline.get("cumulative_exfil"))
    if z is None:
        return 0
    return min(50, round(max(0.0, z - 2) * 10))


# ── token_replay v13 가중치 (Splunk RBA: base + modifier) — 튜닝 포인트 ──
_TR_BASE_COUNTRY = 55      # ip_country 교차 = 지리적 점프 (강한 base)
_TR_BASE_CLASS = 35        # ip_class 교차만 = 회선 점프 (약한 base)
_TR_FANOUT_FREE = 2        # jti 당 IP 2개까지는 가중 없음 (교차 = 최소 2 IP)
_TR_FANOUT_STEP = 10       # IP fan-out 이 free 초과 시 IP 당 +10
_TR_MULTI_JTI_STEP = 12    # 교차한 jti 가 2개 이상이면 추가 토큰당 +12
_TR_CLOUD_BONUS = 15       # 교차 IP 에 데이터센터 클래스 섞이면 +15
_TR_GEO_SPAN_STEP = 10     # 단일 jti 가 3개국 이상이면 추가 국가당 +10
_TR_DATACENTER_CLASSES = {"cloud", "hosting", "vps", "datacenter"}


def factor_token_replay(token_replay_meta):
    """토큰재현(Replay) (결정론, cap 80) — v13: 이진(0/80) → graded 위험 모델.

    base(교차 종류) + modifier(IP fan-out / multi-jti / cloud 개입 / geo span).
    같은 jti 가 단일 클래스 안에서만 보이면 0 (CGNAT IP 로테이션 = 정상).
    """
    if not token_replay_meta:
        return 0

    class_crossing = token_replay_meta.get("jti_count_with_class_crossing", 0)
    country_crossing = token_replay_meta.get("jti_count_with_country_crossing", 0)
    if class_crossing == 0 and country_crossing == 0:
        return 0

    samples = token_replay_meta.get("violating_samples", [])

    # 1) base — 가장 강한 교차 종류
    score = _TR_BASE_COUNTRY if country_crossing > 0 else _TR_BASE_CLASS

    # 2) IP fan-out — 교차 jti 중 최대 distinct IP 수
    max_fanout = max((len(s.get("ip_set", [])) for s in samples),
                     default=_TR_FANOUT_FREE)
    score += max(0, max_fanout - _TR_FANOUT_FREE) * _TR_FANOUT_STEP

    # 3) multi-jti — 교차한 토큰 수 (단발 vs systemic)
    score += max(0, len(samples) - 1) * _TR_MULTI_JTI_STEP

    # 4) cloud 개입 — 교차 IP 에 데이터센터 클래스
    if any(c in _TR_DATACENTER_CLASSES
           for s in samples for c in s.get("ip_class_set", [])):
        score += _TR_CLOUD_BONUS

    # 5) geo span — 단일 jti 최대 국가 수
    max_countries = max((len(s.get("ip_country_set", [])) for s in samples),
                        default=0)
    score += max(0, max_countries - 2) * _TR_GEO_SPAN_STEP

    return min(80, score)


def factor_ip_user_diversity(unique_subs, ip_class, baseline, window_size, metric_key=None):
    """IP-사용자다양성 (Override 100) — 2단계: raw 산출 → ip_class soft cap.

    metric_key: baseline 분포 키. None 이면 IP 단위 기본값(ip_user_diversity_{win}).
                Route B 의 ASN 단위 채점은 "asn_user_diversity_{win}" 을 넘긴다.
    Returns: (score, meta) — meta 는 uba-risk-scores.ip_user_diversity_meta 용.
    """
    dist = baseline.get(metric_key or f"ip_user_diversity_{window_size}")
    z = _zscore(unique_subs, dist)
    cold = z is None

    # 1단계 — raw 점수
    if cold:   # cold start raw fallback (override 100 안 줌)
        if unique_subs >= 10:
            raw = 70
        elif unique_subs >= 5:
            raw = 30
        else:
            raw = 0
    else:
        if z < 3:
            raw = 0
        elif z < 6:
            raw = 70
        else:
            raw = 100

    # 2단계 — ip_class soft cap (fail-open with cap)
    capped = ip_class in IP_USER_DIVERSITY_WHITELIST and raw > IP_USER_DIVERSITY_SOFT_CAP
    score = IP_USER_DIVERSITY_SOFT_CAP if capped else raw

    meta = {
        "raw_score": raw,
        "capped": capped,
        "cap_reason": f"ip_class={ip_class} whitelist soft cap" if capped else None,
        "unique_subs_raw": unique_subs,
        "zscore": round(z, 3) if z is not None else None,
        "baseline_mean": dist.get("mean") if dist else None,
        "baseline_std": dist.get("std") if dist else None,
        "baseline_sample_count": dist.get("sample_count", 0) if dist else 0,
        "cold_start_fallback_applied": cold,
    }
    return score, meta


def factor_response_sensitivity(pii_signal):
    """응답민감도 (Override 100) — backend AOP PII 카운트 기반.

    pii_signal: backend AOP 필터가 별도 로그로 주는 PII 패턴 카운트 dict.
                예: {"doorlock_with_address": True, "email": 12, "phone": 7, ...}
    아직 backend P2 AOP 미연동 → None 이면 0 (graceful degrade).

    Returns: (score, data_exfiltration_detected)
    """
    if not pii_signal:
        return 0, False
    email = pii_signal.get("email", 0)
    phone = pii_signal.get("phone", 0)
    doorlock_addr = pii_signal.get("doorlock_with_address", False)
    if doorlock_addr or email >= 10 or phone >= 10:
        return 70, True
    if phone >= 5:
        return 50, False
    return 0, False


# ────────────────────────────────────────────────────────────────────────────
# 합성
# ────────────────────────────────────────────────────────────────────────────
def _blank_breakdown():
    return {k: 0 for k in FACTOR_KEYS}


def combine(factor_breakdown):
    """7 팩터 → (total_score, dominant_factor).

    최종 = min(100, max(override들, 결정론 + 0.3×통계합)).
    """
    fb = factor_breakdown
    override = max(fb["ip_user_diversity"], fb["response_sensitivity"])
    deterministic = fb["token_violation"] + fb["token_replay"]
    statistical = fb["request_burst"] + fb["response_size_burst"] + fb["cumulative_exfil"]
    additive = deterministic + 0.3 * statistical
    total = min(100, round(max(override, additive)))

    if total == 0:
        return 0, None

    # dominant — 최종 점수에 가장 크게 기여한 팩터
    if override >= additive:
        dominant = ("ip_user_diversity" if fb["ip_user_diversity"] >= fb["response_sensitivity"]
                    else "response_sensitivity")
    else:
        contrib = {
            "token_violation": fb["token_violation"],
            "token_replay": fb["token_replay"],
            "request_burst": 0.3 * fb["request_burst"],
            "response_size_burst": 0.3 * fb["response_size_burst"],
            "cumulative_exfil": 0.3 * fb["cumulative_exfil"],
        }
        dominant = max(contrib, key=contrib.get)
    return total, dominant


# ────────────────────────────────────────────────────────────────────────────
# 타깃별 채점
# ────────────────────────────────────────────────────────────────────────────
def score_user_window(user_event, baseline, pii_signal=None):
    """user-윈도우 집계 doc → user risk doc.

    채점 팩터: token_violation / request_burst / token_replay / response_size_burst
    (+ response_sensitivity, AOP 신호 있을 때). ip_user_diversity/cumulative_exfil 은
    IP 단위 신호라 user doc 에선 0.
    """
    fb = _blank_breakdown()
    tv = user_event.get("token_violation") or {}
    fb["token_violation"] = tv.get("score", 0)
    fb["request_burst"] = factor_request_burst(user_event["request_count"], baseline)
    fb["token_replay"] = factor_token_replay(user_event.get("token_replay_meta"))
    fb["response_size_burst"] = factor_response_size_burst(
        user_event["response_bytes_total"], baseline)
    resp_sens, exfil = factor_response_sensitivity(pii_signal)
    fb["response_sensitivity"] = resp_sens

    total, dominant = combine(fb)
    return {
        # uba-risk-scores 매핑 dynamic:strict — 필드명이 스키마와 정확히 일치해야 한다.
        # dominant_factor 는 영문 키만 저장 (한국어 라벨은 UI 가 FACTOR_KR 로 변환).
        "@timestamp": user_event["window_start"],
        "target_type": "user",
        "target_id": user_event["target_id"],
        "window_start": user_event["window_start"],
        "window_size": user_event["window_size"],
        "total_score": total,
        "dominant_factor": dominant,
        "factor_breakdown": fb,
        "data_exfiltration_detected": exfil,
        "triggered_rules": tv.get("triggered_rules", []),
        "evidence": {
            "token_replay": user_event.get("token_replay_meta", {}),
        },
        "computed_at": datetime.now(UTC).isoformat(),
    }


def score_ip_window(ip_event, baseline):
    """IP-윈도우 또는 ASN-윈도우 집계 doc → risk doc.

    target_type="ip"  → ip_user_diversity (+ cumulative_exfil 24h). S4/S6.
    target_type="asn" → ip_user_diversity (ASN 단위 baseline). Route B — 분산
                        enumeration(S5/S5b). cumulative_exfil 은 IP 24h 누적 전용
                        이라 ASN 에는 적용 안 함 (baseline 단위 불일치).
    token_violation/request_burst/token_replay/response_size_burst 는 user 단위라 0.
    """
    target_type = ip_event.get("target_type", "ip")
    metric_prefix = "asn_user_diversity" if target_type == "asn" else "ip_user_diversity"
    fb = _blank_breakdown()
    iud, iud_meta = factor_ip_user_diversity(
        ip_event["unique_subs_count"], ip_event.get("ip_class"),
        baseline, ip_event["window_size"],
        metric_key=f"{metric_prefix}_{ip_event['window_size']}")
    fb["ip_user_diversity"] = iud
    # cumulative_exfil 은 IP 24h 누적 전용 — ASN 단위는 baseline 불일치라 제외
    if ip_event["window_size"] == "24h" and target_type != "asn":
        fb["cumulative_exfil"] = factor_cumulative_exfil(
            ip_event["response_bytes_total"], baseline)

    total, dominant = combine(fb)
    return {
        "@timestamp": ip_event["window_start"],
        "target_type": target_type,
        "target_id": ip_event["target_id"],
        "window_start": ip_event["window_start"],
        "window_size": ip_event["window_size"],
        "total_score": total,
        "dominant_factor": dominant,
        "factor_breakdown": fb,
        "data_exfiltration_detected": False,
        "ip_user_diversity_meta": iud_meta,
        "ip_class": ip_event.get("ip_class"),
        "ip_asn": ip_event.get("ip_asn"),
        "ip_org": ip_event.get("ip_org"),
        "ip_country": ip_event.get("ip_country"),
        "is_nat_whitelisted": ip_event.get("is_nat_whitelisted"),
        "computed_at": datetime.now(UTC).isoformat(),
    }


# === 테스트 ===
if __name__ == "__main__":
    # baseline — request_burst/response_size_burst 정상 분포 + ip_user_diversity cold start
    baseline = {
        "request_burst": {"mean": 8.8, "std": 6.3, "sample_count": 979, "cold_start": False},
        "response_size_burst": {"mean": 9000.0, "std": 2500.0, "sample_count": 979, "cold_start": False},
        "cumulative_exfil": {"mean": 40000.0, "std": 12000.0, "sample_count": 150, "cold_start": False},
        "ip_user_diversity_5min": {"sample_count": 32, "cold_start": True},
        "ip_user_diversity_24h": {"sample_count": 32, "cold_start": True},
        "asn_user_diversity_5min": {"sample_count": 12, "cold_start": True},
    }

    print("=== 정상 user-윈도우 ===")
    normal = score_user_window({
        "target_id": "140000511", "window_start": "t", "window_size": "5min",
        "request_count": 12, "response_bytes_total": 9500,
        "token_replay_meta": {"jti_count_with_class_crossing": 0, "jti_count_with_country_crossing": 0},
        "token_violation": {"score": 0, "triggered_rules": [], "violating_samples": []},
    }, baseline)
    print(f"  total={normal['total_score']} dominant={normal['dominant_factor']}")
    assert normal["total_score"] == 0, "정상 user → 0"

    print("=== S2 하이재킹 전형 (ip_class 교차 / residential / IP 2개) ===")
    s2 = score_user_window({
        "target_id": "140000511", "window_start": "t", "window_size": "5min",
        "request_count": 8, "response_bytes_total": 4000,
        "token_replay_meta": {
            "jti_count_with_class_crossing": 1, "jti_count_with_country_crossing": 0,
            "violating_samples": [
                {"jti": "j1", "crossing_type": "ip_class",
                 "ip_set": ["222.110.15.50", "175.223.10.4"],
                 "ip_class_set": ["cgnat_kr", "telecom_kr"],
                 "ip_country_set": ["KR"]},
            ],
        },
        "token_violation": {"score": 0, "triggered_rules": [], "violating_samples": []},
    }, baseline)
    print(f"  total={s2['total_score']} dominant={s2['dominant_factor']}")
    assert s2["total_score"] == 35 and s2["dominant_factor"] == "token_replay", "S2 전형 → token_replay 35"

    print("=== S2 하이재킹 심화 (ip_country 교차 + cloud + IP fan-out 4 + jti 2) ===")
    s2x = score_user_window({
        "target_id": "140000511", "window_start": "t", "window_size": "5min",
        "request_count": 8, "response_bytes_total": 4000,
        "token_replay_meta": {
            "jti_count_with_class_crossing": 2, "jti_count_with_country_crossing": 2,
            "violating_samples": [
                {"jti": "j1", "crossing_type": "ip_country",
                 "ip_set": ["222.110.15.50", "73.55.20.40", "45.32.1.9", "104.28.0.1"],
                 "ip_class_set": ["cgnat_kr", "cloud"],
                 "ip_country_set": ["KR", "US"]},
                {"jti": "j2", "crossing_type": "ip_country",
                 "ip_set": ["222.110.15.50", "73.55.20.40"],
                 "ip_class_set": ["cgnat_kr", "residential"],
                 "ip_country_set": ["KR", "US"]},
            ],
        },
        "token_violation": {"score": 0, "triggered_rules": [], "violating_samples": []},
    }, baseline)
    print(f"  total={s2x['total_score']} dominant={s2x['dominant_factor']}")
    assert s2x["total_score"] == 80 and s2x["dominant_factor"] == "token_replay", "S2 심화 → token_replay 80 (cap)"

    print("=== S4 enumeration ip-윈도우 (cloud, unique_subs 100) ===")
    s4 = score_ip_window({
        "target_id": "13.124.0.9", "window_start": "t", "window_size": "5min",
        "unique_subs_count": 100, "response_bytes_total": 250000, "ip_class": "cloud",
        "ip_asn": "AS16509", "ip_org": "AWS", "ip_country": "US", "is_nat_whitelisted": False,
    }, baseline)
    print(f"  total={s4['total_score']} dominant={s4['dominant_factor']} raw={s4['ip_user_diversity_meta']['raw_score']}")
    assert s4["total_score"] == 70, "S4 cloud cold-start raw fallback (unique_subs>=10 → 70)"
    assert s4["dominant_factor"] == "ip_user_diversity"

    print("=== S5/S5b 분산 enumeration ASN-윈도우 (Route B, unknown, unique_subs 40) ===")
    s5 = score_ip_window({
        "target_type": "asn", "target_id": "AS20473", "window_start": "t",
        "window_size": "5min", "unique_subs_count": 40, "response_bytes_total": 96000,
        "ip_class": "unknown", "ip_asn": "AS20473", "ip_org": "Vultr",
        "ip_country": "US", "is_nat_whitelisted": False,
    }, baseline)
    print(f"  total={s5['total_score']} dominant={s5['dominant_factor']} "
          f"target_type={s5['target_type']} raw={s5['ip_user_diversity_meta']['raw_score']}")
    assert s5["target_type"] == "asn", "ASN risk doc target_type 유지"
    assert s5["total_score"] == 70, "S5 ASN cold-start raw fallback (unique_subs>=10 → 70)"
    assert s5["dominant_factor"] == "ip_user_diversity"

    print("=== S7 카페 NAT ip-윈도우 (cgnat_kr, unique_subs 50 → soft cap) ===")
    s7 = score_ip_window({
        "target_id": "175.197.50.12", "window_start": "t", "window_size": "5min",
        "unique_subs_count": 50, "response_bytes_total": 80000, "ip_class": "cgnat_kr",
        "ip_asn": "AS4766", "ip_org": "KT", "ip_country": "KR", "is_nat_whitelisted": True,
    }, baseline)
    print(f"  total={s7['total_score']} raw={s7['ip_user_diversity_meta']['raw_score']} "
          f"capped={s7['ip_user_diversity_meta']['capped']}")
    assert s7["total_score"] == 30 and s7["ip_user_diversity_meta"]["capped"], "S7 cgnat_kr soft cap 30"

    print("\n계약 점검 통과 ✅ (정상 0 / S2 전형 35 / S2 심화 80 / S4 70 / S5·S5b ASN 70 / S7 soft cap 30)")
