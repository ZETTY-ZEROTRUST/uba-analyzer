"""
user_profile.py — 사용자별 누적 프로필 (uba-user-profiles 인덱스)

설계 의도:
  - baseline_store 는 "전역 분포" — 모든 사용자의 평균. 개인차를 못 본다.
  - user-profiles 는 "개인 분포" — 각 사용자의 평소 패턴. 사용자 A 가 평소 100건/시간
    이면 50건도 정상, 사용자 B 가 평소 5건이면 50건이 비정상.
  - factor_engine 의 z-score 가 전역 → 개인 으로 한 단계 올라가는 발판.
  - 06_ml_design.md §3 "사용자별 정규화 (핵심)" 의 코드 구현.

저장 정책 (보안/프라이버시):
  - raw JWT bearer 토큰은 절대 저장하지 않는다 — jti / lsid / 클레임 메타만.
  - 진성 PII (이메일/이름/전화)는 auth-server 의 user DB 가 별도 관리 — 이 모듈은
    "행동 관측 결과 + 토큰 메타" 만 책임.
  - known_jtis / known_lsids 는 MAX_KEPT 개로 자동 트리밍 (무한 증가 방지).

문서 ID = user_id (jwt.sub). 즉 `GET /uba-user-profiles/_doc/140000511` 한 줄로 조회.

흐름:
  pipeline.py — Phase 2 끝에서:
    for ue in user_events:
        user_profile.update_from_window(es, ue)   ← 매 윈도우 누적
    for risk_doc in risk_docs:
        if risk_doc["total_score"] >= ALERT_THRESHOLD:
            user_profile.record_alert(es, risk_doc)   ← 알람 발생 시 risk 갱신
"""
import logging
import math
import os
from collections import Counter
from datetime import datetime, timedelta, timezone, UTC

from elasticsearch import Elasticsearch
from dotenv import load_dotenv
import urllib3

load_dotenv()
urllib3.disable_warnings()

ES_HOST = os.environ.get("ES_HOST", "https://10.0.41.10:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "")

INDEX = "uba-user-profiles"

# 트리밍 한도 — 무한 증가 방지 (가장 최근 것 유지)
MAX_KEPT_JTIS = 50          # known_jtis 최근 50개
MAX_KEPT_LSIDS = 20         # known_lsids 최근 20개
MAX_KEPT_ENDPOINTS = 30     # typical_endpoints 상위 30개 (count 기준)
MAX_KEPT_IPS = 20           # known_ips 상위 20개

# trust_level enum (06_ml_design.md §5.2 와 일치)
TRUST_NEW = "new"                  # 가입 0~7일 — grace period
TRUST_LEARNING = "learning"        # 7~14일 — 글로벌 baseline
TRUST_ESTABLISHED = "established"  # 14일+ — 개인 baseline
TRUST_SUSPICIOUS = "suspicious"    # 누적 알람 있음

SCHEMA_VERSION = "v1"
PROFILE_VERSION = "v1"

logger = logging.getLogger("user-profile")


def get_es_client():
    return Elasticsearch([ES_HOST], basic_auth=(ES_USER, ES_PASS), verify_certs=False)


# ────────────────────────────────────────────────────────────────────────────
# 조회
# ────────────────────────────────────────────────────────────────────────────
def get_profile(es, user_id):
    """user_id 의 프로필 doc 조회. 없으면 None."""
    try:
        result = es.get(index=INDEX, id=str(user_id))
        return result["_source"]
    except Exception:
        return None


def exists(es, user_id):
    """프로필 존재 여부 (cold start 분기용)."""
    try:
        return es.exists(index=INDEX, id=str(user_id))
    except Exception:
        return False


# ────────────────────────────────────────────────────────────────────────────
# 순환 통계 (시간대 — 자정 경계 처리)
# ────────────────────────────────────────────────────────────────────────────
def _circular_stats(hours):
    """0~23 시 리스트 → (circular_mean, circular_stdev). 06_ml_design.md §3.3 의 구현.

    시간은 직선이 아니라 원형이므로 단순 평균은 22~02시 사용자를 오전 12시로 평가한다.
    각도 변환 → sin/cos 평균 → arctan2 로 원형 평균을 구한다.
    """
    if not hours:
        return None, None
    radians = [h * 2 * math.pi / 24 for h in hours]
    sin_mean = sum(math.sin(r) for r in radians) / len(radians)
    cos_mean = sum(math.cos(r) for r in radians) / len(radians)
    mean_rad = math.atan2(sin_mean, cos_mean)
    circular_mean = (mean_rad * 24 / (2 * math.pi)) % 24

    # 합벡터 길이 R — 1에 가까우면 집중, 0에 가까우면 분산
    R = math.sqrt(sin_mean ** 2 + cos_mean ** 2)
    if R >= 1.0:
        circular_stdev = 0.0
    elif R <= 0.0:
        circular_stdev = 12.0   # 완전 분산 — 최대값
    else:
        circular_stdev = math.sqrt(-2 * math.log(R)) * 24 / (2 * math.pi)
    return round(circular_mean, 3), round(circular_stdev, 3)


# ────────────────────────────────────────────────────────────────────────────
# trust_level 계산
# ────────────────────────────────────────────────────────────────────────────
def compute_trust_level(profile):
    """프로필 doc → trust_level. 알람 누적 시 새/학습 단계여도 suspicious 로 승격."""
    if not profile:
        return TRUST_NEW
    risk = profile.get("risk") or {}
    if (risk.get("total_alerts", 0) > 0
            or risk.get("alerts_last_30d", 0) > 0):
        return TRUST_SUSPICIOUS
    first_seen = profile.get("first_seen")
    if not first_seen:
        return TRUST_NEW
    try:
        seen_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        age_days = (datetime.now(UTC) - seen_dt).days
    except Exception:
        return TRUST_NEW
    if age_days < 7:
        return TRUST_NEW
    if age_days < 14:
        return TRUST_LEARNING
    return TRUST_ESTABLISHED


# ────────────────────────────────────────────────────────────────────────────
# 윈도우 → 프로필 누적 업데이트
# ────────────────────────────────────────────────────────────────────────────
def _trim_keep_recent(items, max_kept):
    """리스트 끝쪽을 유지 (최근). dedup 한 뒤 잘라낸다."""
    seen = set()
    out = []
    for item in reversed(items):   # 뒤에서부터 = 최신부터
        if item not in seen:
            seen.add(item)
            out.append(item)
        if len(out) >= max_kept:
            break
    return list(reversed(out))     # 다시 시간순


def _merge_endpoints(existing, new_endpoints, now_iso):
    """typical_endpoints nested 병합 — count 누적, last_seen 갱신.

    existing: [{"path", "count", "last_seen"}, ...] 또는 None
    new_endpoints: {path: count} dict
    """
    by_path = {e["path"]: e for e in (existing or [])}
    for path, n in new_endpoints.items():
        if path in by_path:
            by_path[path]["count"] += n
            by_path[path]["last_seen"] = now_iso
        else:
            by_path[path] = {"path": path, "count": n, "last_seen": now_iso}
    # count 내림차순 상위 MAX_KEPT_ENDPOINTS
    sorted_eps = sorted(by_path.values(), key=lambda e: -e["count"])
    return sorted_eps[:MAX_KEPT_ENDPOINTS]


def _merge_ips(existing, observed_ip_metas, now_iso):
    """known_ips nested 병합 — 새 IP는 추가, 기존 IP는 count 증가 + last_seen 갱신.

    observed_ip_metas: [{"ip", "ip_class", "ip_asn", "ip_country", "count"}, ...]
    """
    by_ip = {e["ip"]: e for e in (existing or [])}
    for meta in observed_ip_metas:
        ip = meta["ip"]
        if ip in by_ip:
            by_ip[ip]["count"] += meta.get("count", 1)
            by_ip[ip]["last_seen"] = now_iso
            # 메타가 비어 있으면 새 값으로 채움
            for k in ("ip_class", "ip_asn", "ip_country"):
                if not by_ip[ip].get(k) and meta.get(k):
                    by_ip[ip][k] = meta[k]
        else:
            by_ip[ip] = {
                "ip": ip,
                "ip_class": meta.get("ip_class"),
                "ip_asn": meta.get("ip_asn"),
                "ip_country": meta.get("ip_country"),
                "first_seen": now_iso,
                "last_seen": now_iso,
                "count": meta.get("count", 1),
            }
    sorted_ips = sorted(by_ip.values(), key=lambda e: -e["count"])
    return sorted_ips[:MAX_KEPT_IPS]


def _extract_jwt_meta(user_event):
    """user_event(event_aggregator 출력) → JWT 메타 추출용 도우미.

    event_aggregator 가 jti_set/alg_set/kid_set 까지만 갖고 있어서, lsid/scope/acr/amr/aud
    는 user_event 안에 따로 받아오지 못한다. 이 함수는 user_event 가 추가로 raw_logs
    리스트를 들고 있을 때만 추출한다 (옵션). pipeline.py 가 raw_logs 를 user_event 에
    실어 보내면 풍부한 메타를 학습한다.
    """
    raw_logs = user_event.get("_raw_logs") or []
    if not raw_logs:
        return {}
    g = raw_logs[0]
    return {
        "typical_aud": g.get("audiences"),
        "typical_iss": g.get("issuer"),
        "typical_client_id": g.get("client_id"),
        "typical_acr": g.get("acr"),
        "typical_amr": g.get("amr"),
        "typical_scopes": g.get("scopes"),
        "typical_token_lifetime_sec": (
            g.get("jwt_expires_at", 0) - g.get("jwt_issued_at", 0)
            if g.get("jwt_expires_at") and g.get("jwt_issued_at") else None
        ),
        "first_auth_time_epoch": min((g.get("auth_time") for g in raw_logs
                                      if g.get("auth_time")), default=None),
        "last_auth_time_epoch": max((g.get("auth_time") for g in raw_logs
                                     if g.get("auth_time")), default=None),
        "uri_counts": dict(Counter((g.get("uri") or "").split("?")[0]
                                   for g in raw_logs if g.get("uri"))),
        "hours": [
            datetime.fromtimestamp(g["receive_epoch"], UTC).hour
            for g in raw_logs if g.get("receive_epoch")
        ],
        "status_counts": Counter(g.get("status", 0) for g in raw_logs),
        "ip_metas": [
            {"ip": g["client_ip"], "ip_class": g.get("ip_class"),
             "ip_asn": g.get("ip_asn"), "ip_country": g.get("ip_country"),
             "count": 1}
            for g in raw_logs if g.get("client_ip")
        ],
    }


def update_from_window(es, user_event):
    """user-윈도우 집계 doc 1개 → 해당 사용자의 프로필 누적 업데이트.

    Args:
        user_event: event_aggregator.aggregate_user_events() 출력 dict 1건.
                    (선택) `_raw_logs` 키에 그 윈도우의 정규화 로그 리스트가 실려 있으면
                    JWT 메타 / 시간대 / endpoint 분포까지 학습. 없으면 기본 카운트만.

    Returns:
        {"created": bool, "updated": bool, "user_id": str}
    """
    user_id = str(user_event.get("target_id") or "")
    if not user_id:
        return {"created": False, "updated": False, "user_id": ""}

    now = datetime.now(UTC)
    now_iso = now.isoformat()
    existing = get_profile(es, user_id)
    created = existing is None
    prof = existing or {
        "user_id": user_id,
        "first_seen": now_iso,
        "jwt_pattern": {"known_jtis": [], "known_lsids": [], "known_kids": []},
        "behavior": {
            "requests_total": 0, "success_total": 0, "error_total": 0,
            "active_hours_set": [], "typical_endpoints": [],
            "status_distribution": {"s2xx": 0, "s3xx": 0, "s4xx": 0, "s5xx": 0},
            "response_bytes_total": 0, "response_bytes_max": 0,
        },
        "location": {"known_ips": [], "known_countries": [],
                     "known_asns": [], "known_ip_classes": []},
        "risk": {"total_alerts": 0, "alerts_last_24h": 0, "alerts_last_7d": 0,
                 "alerts_last_30d": 0, "data_exfiltration_ever": False,
                 "anomaly_score": 0.0, "trust_level": TRUST_NEW},
        "ingest_meta": {"data_points_count": 0,
                        "profile_version": PROFILE_VERSION,
                        "schema_version": SCHEMA_VERSION},
    }

    # === 기본 카운트 (raw_logs 없어도 가능) ===
    req = user_event.get("request_count", 0)
    succ = user_event.get("success_count", 0)
    err = user_event.get("error_count", 0)
    prof["behavior"]["requests_total"] += req
    prof["behavior"]["success_total"] += succ
    prof["behavior"]["error_total"] += err
    total = prof["behavior"]["requests_total"]
    prof["behavior"]["error_ratio"] = round(
        prof["behavior"]["error_total"] / total, 4) if total else 0.0

    rb = user_event.get("response_bytes_total", 0)
    prof["behavior"]["response_bytes_total"] += rb
    prof["behavior"]["response_bytes_max"] = max(
        prof["behavior"].get("response_bytes_max", 0),
        user_event.get("response_bytes_max", 0))
    prof["behavior"]["response_bytes_avg"] = round(
        prof["behavior"]["response_bytes_total"] / total, 1) if total else 0.0

    # === jti / lsid / kid 누적 ===
    jp = prof["jwt_pattern"]
    jp["known_jtis"] = _trim_keep_recent(
        jp.get("known_jtis", []) + (user_event.get("jti_set") or []),
        MAX_KEPT_JTIS)
    jp["known_kids"] = _trim_keep_recent(
        jp.get("known_kids", []) + (user_event.get("kid_set") or []), 5)
    jp["known_jti_count"] = len(jp["known_jtis"])
    jp["known_lsid_count"] = len(jp.get("known_lsids", []))

    # === raw_logs 가 있으면 풍부한 메타 학습 ===
    meta = _extract_jwt_meta(user_event)
    if meta:
        if meta.get("typical_aud"):
            jp["typical_aud"] = meta["typical_aud"]
        if meta.get("typical_iss"):
            jp["typical_iss"] = meta["typical_iss"]
        if meta.get("typical_client_id"):
            jp["typical_client_id"] = meta["typical_client_id"]
        if meta.get("typical_acr"):
            jp["typical_acr"] = meta["typical_acr"]
        if meta.get("typical_amr"):
            jp["typical_amr"] = meta["typical_amr"]
        if meta.get("typical_scopes"):
            jp["typical_scopes"] = meta["typical_scopes"]
        if meta.get("typical_token_lifetime_sec"):
            jp["typical_token_lifetime_sec"] = meta["typical_token_lifetime_sec"]
        if meta.get("first_auth_time_epoch"):
            at = datetime.fromtimestamp(meta["first_auth_time_epoch"], UTC).isoformat()
            if not jp.get("first_auth_time"):
                jp["first_auth_time"] = at
        if meta.get("last_auth_time_epoch"):
            jp["last_auth_time"] = datetime.fromtimestamp(
                meta["last_auth_time_epoch"], UTC).isoformat()

        # 시간대 — 활동 시각 누적
        hours = meta.get("hours") or []
        existing_hours = set(prof["behavior"].get("active_hours_set", []))
        existing_hours.update(hours)
        prof["behavior"]["active_hours_set"] = sorted(existing_hours)
        prof["behavior"]["active_hour_count"] = len(existing_hours)
        # circular 통계 — 누적된 모든 활동 시각의 분포
        cm, cs = _circular_stats(list(existing_hours))
        if cm is not None:
            prof["behavior"]["circular_mean_hour"] = cm
            prof["behavior"]["circular_stdev_hour"] = cs

        # endpoint 누적
        uri_counts = meta.get("uri_counts") or {}
        prof["behavior"]["typical_endpoints"] = _merge_endpoints(
            prof["behavior"].get("typical_endpoints"), uri_counts, now_iso)
        prof["behavior"]["unique_uri_count"] = len(
            prof["behavior"]["typical_endpoints"])

        # status 분포
        sd = prof["behavior"]["status_distribution"]
        for status, n in (meta.get("status_counts") or {}).items():
            try:
                bucket = f"s{int(status) // 100}xx"
                if bucket in sd:
                    sd[bucket] += n
            except (ValueError, TypeError):
                pass

        # IP 이력
        ip_metas = meta.get("ip_metas") or []
        prof["location"]["known_ips"] = _merge_ips(
            prof["location"].get("known_ips"), ip_metas, now_iso)
        prof["location"]["known_ip_count"] = len(prof["location"]["known_ips"])
        # 보조 keyword 리스트들
        countries = set(prof["location"].get("known_countries", []))
        asns = set(prof["location"].get("known_asns", []))
        classes = set(prof["location"].get("known_ip_classes", []))
        for ip_entry in prof["location"]["known_ips"]:
            if ip_entry.get("ip_country"):
                countries.add(ip_entry["ip_country"])
            if ip_entry.get("ip_asn"):
                asns.add(ip_entry["ip_asn"])
            if ip_entry.get("ip_class"):
                classes.add(ip_entry["ip_class"])
        prof["location"]["known_countries"] = sorted(countries)
        prof["location"]["known_asns"] = sorted(asns)
        prof["location"]["known_ip_classes"] = sorted(classes)
        # primary_ip = count 최대
        if prof["location"]["known_ips"]:
            prof["location"]["primary_ip"] = prof["location"]["known_ips"][0]["ip"]

    # === 윈도우당 요청 수의 분포 — running mean/stdev (Welford 단순화) ===
    n = prof["ingest_meta"].get("data_points_count", 0) + 1
    mean_prev = prof["behavior"].get("requests_per_window_mean", 0.0)
    delta = req - mean_prev
    mean_new = mean_prev + delta / n
    # 표준편차는 단순화 — running sum of squared diffs 미보관, 근사값으로 대체
    # (정확한 stdev 가 필요하면 ingest_meta 에 m2 누적 필드 추가 권장)
    prof["behavior"]["requests_per_window_mean"] = round(mean_new, 3)
    prof["behavior"]["requests_per_window_max"] = max(
        prof["behavior"].get("requests_per_window_max", 0), req)

    # === 시간 메타 + trust_level ===
    prof["last_seen"] = now_iso
    prof["last_updated"] = now_iso
    if "first_seen" not in prof:
        prof["first_seen"] = now_iso
    try:
        first_dt = datetime.fromisoformat(prof["first_seen"].replace("Z", "+00:00"))
        prof["total_active_days"] = max(1, (now - first_dt).days + 1)
    except Exception:
        prof["total_active_days"] = 1

    prof["ingest_meta"]["data_points_count"] = n
    prof["risk"]["trust_level"] = compute_trust_level(prof)
    prof["user_id"] = user_id

    # === 저장 (upsert) ===
    try:
        es.index(index=INDEX, id=user_id, document=prof)
        return {"created": created, "updated": True, "user_id": user_id}
    except Exception as e:
        logger.error(f"user_profile upsert 실패 (user {user_id}): {e}")
        return {"created": False, "updated": False, "user_id": user_id}


# ────────────────────────────────────────────────────────────────────────────
# 알람 발생 시 risk 갱신
# ────────────────────────────────────────────────────────────────────────────
def record_alert(es, risk_doc):
    """risk_scorer 가 만든 risk_doc (total_score >= threshold) → 해당 user 프로필 risk 갱신.

    target_type=ip 인 risk_doc 은 건너뜀 — IP 단위라 user 매칭이 어렵다.
    """
    if risk_doc.get("target_type") != "user":
        return None
    user_id = str(risk_doc.get("target_id") or "")
    if not user_id:
        return None

    profile = get_profile(es, user_id)
    if not profile:
        # 알람만 들어왔는데 프로필 없으면 빈 프로필 만들고 risk 만 채움
        profile = {
            "user_id": user_id,
            "first_seen": datetime.now(UTC).isoformat(),
            "jwt_pattern": {}, "behavior": {}, "location": {},
            "risk": {"total_alerts": 0, "alerts_last_24h": 0, "alerts_last_7d": 0,
                     "alerts_last_30d": 0, "max_score_seen": 0,
                     "data_exfiltration_ever": False, "anomaly_score": 0.0,
                     "trust_level": TRUST_NEW},
            "ingest_meta": {"data_points_count": 0,
                            "profile_version": PROFILE_VERSION,
                            "schema_version": SCHEMA_VERSION},
        }

    risk = profile.setdefault("risk", {})
    risk["total_alerts"] = risk.get("total_alerts", 0) + 1
    risk["last_alert_at"] = datetime.now(UTC).isoformat()
    risk["last_alert_dominant_factor"] = risk_doc.get("dominant_factor")
    triggered = risk_doc.get("triggered_rules") or []
    if triggered:
        risk["last_alert_rule"] = triggered[0]

    score = risk_doc.get("total_score", 0)
    risk["max_score_seen"] = max(risk.get("max_score_seen", 0), score)

    level = risk_doc.get("attacker_level")
    if level:
        prev = risk.get("max_attacker_level_seen")
        # 단순 우선순위 — L4 > L4(Slow & Low) > L2 > L0
        order = {"L4": 4, "L4(Slow & Low)": 3, "L2": 2, "L0": 1}
        if not prev or order.get(level, 0) > order.get(prev, 0):
            risk["max_attacker_level_seen"] = level

    # severity 추정 (factor_breakdown 기반)
    if score >= 80:
        sev = "critical"
    elif score >= 50:
        sev = "high"
    elif score >= 30:
        sev = "medium"
    else:
        sev = "low"
    sev_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    prev_sev = risk.get("max_severity_seen")
    if not prev_sev or sev_order.get(sev, 0) > sev_order.get(prev_sev, 0):
        risk["max_severity_seen"] = sev

    if risk_doc.get("data_exfiltration_detected"):
        risk["data_exfiltration_ever"] = True

    profile["last_updated"] = datetime.now(UTC).isoformat()
    risk["trust_level"] = compute_trust_level(profile)

    try:
        es.index(index=INDEX, id=user_id, document=profile)
        return {"updated": True, "user_id": user_id, "total_alerts": risk["total_alerts"]}
    except Exception as e:
        logger.error(f"user_profile record_alert 실패 (user {user_id}): {e}")
        return {"updated": False, "user_id": user_id}


# ────────────────────────────────────────────────────────────────────────────
# 배치 헬퍼 — pipeline.py 가 한 번에 호출
# ────────────────────────────────────────────────────────────────────────────
def update_from_user_events(es, user_events, raw_logs_by_user=None):
    """user_events 리스트 전체를 프로필로 누적. 옵션으로 raw_logs 도 전달 가능.

    Args:
        user_events: event_aggregator.aggregate_user_events() 출력 리스트.
        raw_logs_by_user: {user_id: [logs...]} dict. 있으면 user_event 에 _raw_logs
                          주입 후 update — JWT 메타 / 시간대 / endpoint 학습.
    """
    raw_logs_by_user = raw_logs_by_user or {}
    results = {"created": 0, "updated": 0, "failed": 0}
    for ue in user_events:
        uid = str(ue.get("target_id") or "")
        if uid and uid in raw_logs_by_user:
            ue["_raw_logs"] = raw_logs_by_user[uid]
        r = update_from_window(es, ue)
        if r.get("created"):
            results["created"] += 1
        if r.get("updated"):
            results["updated"] += 1
        else:
            results["failed"] += 1
    return results


def record_alerts_from_risk_docs(es, risk_docs, threshold=50):
    """risk_docs 에서 threshold 넘는 user 타깃만 골라 record_alert."""
    results = {"recorded": 0, "skipped": 0}
    for d in risk_docs:
        if d.get("target_type") != "user":
            results["skipped"] += 1
            continue
        if d.get("total_score", 0) < threshold:
            results["skipped"] += 1
            continue
        if record_alert(es, d):
            results["recorded"] += 1
    return results


# ────────────────────────────────────────────────────────────────────────────
# 테스트 — ES 없이도 로직 검증 가능한 부분
# ────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== circular stats 테스트 ===")
    # 22~02시 집중 사용자
    night = [22, 23, 23, 0, 1, 2, 22, 23, 0, 1]
    cm, cs = _circular_stats(night)
    print(f"  22~02시 사용자: mean={cm}h stdev={cs}h (직선 평균이면 ~9h 가 나오는 게 정상)")
    assert cm > 20 or cm < 4, f"자정 근처여야: got {cm}"

    # 13시 집중 사용자
    day = [12, 13, 13, 13, 14, 13, 12, 14]
    cm, cs = _circular_stats(day)
    print(f"  13시 사용자: mean={cm}h stdev={cs}h")
    assert 12 <= cm <= 14, f"13시 근처여야: got {cm}"

    print("\n=== trust_level 테스트 ===")
    from datetime import timedelta as td
    base = datetime.now(UTC)
    cases = [
        ({"first_seen": (base - td(days=3)).isoformat(), "risk": {"total_alerts": 0}}, TRUST_NEW),
        ({"first_seen": (base - td(days=10)).isoformat(), "risk": {"total_alerts": 0}}, TRUST_LEARNING),
        ({"first_seen": (base - td(days=20)).isoformat(), "risk": {"total_alerts": 0}}, TRUST_ESTABLISHED),
        ({"first_seen": (base - td(days=20)).isoformat(), "risk": {"total_alerts": 1}}, TRUST_SUSPICIOUS),
        ({"first_seen": (base - td(days=3)).isoformat(), "risk": {"total_alerts": 5}}, TRUST_SUSPICIOUS),
    ]
    for prof, expected in cases:
        got = compute_trust_level(prof)
        status = "OK" if got == expected else "FAIL"
        print(f"  [{status}] {prof['first_seen'][:10]} alerts={prof['risk']['total_alerts']} → {got} (expected {expected})")
        assert got == expected

    print("\n=== endpoint merge 테스트 ===")
    existing = [{"path": "/api/users/me", "count": 100, "last_seen": "2026-05-01T00:00:00+00:00"}]
    new = {"/api/users/me": 5, "/api/products": 3}
    merged = _merge_endpoints(existing, new, "2026-05-17T00:00:00+00:00")
    print(f"  병합 결과: {merged}")
    assert any(e["path"] == "/api/users/me" and e["count"] == 105 for e in merged)
    assert any(e["path"] == "/api/products" and e["count"] == 3 for e in merged)

    print("\n=== JTI 트리밍 테스트 ===")
    jtis = [f"jti-{i}" for i in range(80)]
    trimmed = _trim_keep_recent(jtis, MAX_KEPT_JTIS)
    print(f"  80개 → {len(trimmed)}개 유지 (최근 {MAX_KEPT_JTIS}개)")
    assert len(trimmed) == MAX_KEPT_JTIS
    assert trimmed[-1] == "jti-79", "가장 최근 jti 가 끝에 와야"
    assert trimmed[0] == f"jti-{80 - MAX_KEPT_JTIS}", "오래된 건 잘려나가야"

    print("\n계약 점검 통과 ✅ (circular hours / trust_level / endpoint merge / JTI 트리밍)")
    print("\n실 ES 테스트는 ES 가 켜져 있을 때 다음 스니펫으로:")
    print("  from user_profile import get_es_client, update_from_window")
    print("  es = get_es_client()")
    print("  update_from_window(es, {'target_id': '140000511', 'request_count': 12, ...})")
