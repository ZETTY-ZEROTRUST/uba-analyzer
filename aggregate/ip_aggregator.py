"""
ip_aggregator.py — Phase 1: 정규화 로그 → IP별 다중 윈도우 집계

log_fetcher.normalize_log() 출력을 client_ip 단위로 묶어 ip_user_diversity 팩터의
입력 doc 을 만든다. (uba-events 인덱스, target_type="ip")

설계 의도:
  - IP 단위 집계의 핵심 지표는 unique_subs — "한 IP 가 몇 명의 서로 다른
    user(sub)를 건드렸나". 단일 IP enumeration(S4)/저속 유출(S6)의 메인 신호.
  - ★ 다중 윈도우(5min/1h/24h): 같은 IP 를 세 개의 시간 렌즈로 본다.
    5min = 즉각 공격(S4) 포착, 24h = 분당 1~2건짜리 저속 유출(S6) 포착.
    한 윈도우만 쓰면 둘 중 하나는 반드시 놓친다 (멘토 4단계 설계).
  - ua_set(User-Agent 다양성)도 모은다 — 단일 IP 의 정상 NAT(가정/카페) 판정
    근거. 사람이 여럿이면 기기/브라우저(UA)도 다양하다. attack 은 보통 단일 UA.
"""
import re
from collections import defaultdict
from datetime import datetime, timezone

# 윈도우 라벨 → 초. ip_user_diversity 는 이 세 윈도우 각각으로 산출된다.
WINDOWS = {"5min": 300, "1h": 3600, "24h": 86400}

SENSITIVE_URI_RE = re.compile(r"/(addresses|orders)/\d+")


def _epoch_to_iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def aggregate_ip_events(logs):
    """정규화 로그 리스트 → IP-윈도우 집계 doc 리스트.

    같은 로그 집합이 5min/1h/24h 세 윈도우로 각각 집계된다 (윈도우당 별도 doc).
    """
    docs = []
    for label, secs in WINDOWS.items():
        buckets = defaultdict(list)
        for g in logs:
            ip = g.get("client_ip")
            ep = g.get("receive_epoch")
            if not ip or ep is None:
                continue
            win = (ep // secs) * secs
            buckets[(ip, win)].append(g)
        for (ip, win), grp in buckets.items():
            docs.append(_build_target_doc("ip", ip, win, label, grp))
    return docs


def aggregate_asn_events(logs):
    """정규화 로그 → ASN-윈도우 집계 doc 리스트 (Route B — 분산 enumeration 탐지).

    IP 분산 공격(S5/S5b)은 개별 IP 의 unique_subs 를 희석해 ip_user_diversity 를
    회피한다. 공격 IP 들이 속한 ASN 으로 다시 묶으면 다양성이 재집결한다.
      - cgnat_kr(통신사 ASN): 정상 사용자 수백만이 공유 → ASN 집계가 무의미하고
        오탐만 낸다 → 제외 (KT 200명이 자기 정보 조회해도 ASN doc 자체가 안 생김).
      - ip_asn 미상(null): 분류 불가 잡탕 → 제외.
    sub 가 순차냐 랜덤이냐는 무관(unique 개수만 셈) — S5·S5b 를 동일하게 잡는다.
    """
    docs = []
    for label, secs in WINDOWS.items():
        buckets = defaultdict(list)
        for g in logs:
            asn = g.get("ip_asn")
            ep = g.get("receive_epoch")
            if not asn or ep is None:
                continue
            if g.get("ip_class") == "cgnat_kr":   # 통신사 ASN 제외 (오탐 방지)
                continue
            win = (ep // secs) * secs
            buckets[(asn, win)].append(g)
        for (asn, win), grp in buckets.items():
            docs.append(_build_target_doc("asn", asn, win, label, grp))
    return docs


def _build_target_doc(target_type, target_id, window_start, window_size, group):
    """한 (타깃, 윈도우) 버킷 → 집계 doc. 타깃 = IP(client_ip) 또는 ASN(ip_asn)."""
    sub_set = sorted({g["user_id"] for g in group if g.get("user_id")})
    ua_set = sorted({g["user_agent"] for g in group if g.get("user_agent")})
    methods = sorted({g["method"] for g in group if g.get("method")})
    bytes_total = sum(g["bytes_sent"] for g in group)
    suspicious = sum(1 for g in group if SENSITIVE_URI_RE.search(g.get("uri") or ""))

    # IP 메타데이터(ip_class/asn 등)는 같은 IP 의 로그면 동일 → 첫 로그 기준
    head = group[0]
    window_iso = _epoch_to_iso(window_start)

    return {
        # uba-events 매핑 dynamic:strict — target_type + target_id 일반 키 (user/ip 공통).
        "@timestamp": window_iso,
        "target_type": target_type,
        "target_id": target_id,
        "window_start": window_iso,
        "window_size": window_size,

        "request_count": len(group),
        "error_count": sum(1 for g in group if g["status"] >= 400),
        "suspicious_uri_count": suspicious,

        "unique_subs_count": len(sub_set),  # ★ ip_user_diversity 핵심 입력
        "sub_set": sub_set,

        "response_bytes_total": bytes_total,
        "request_methods": methods,
        "ua_set": ua_set,                   # UA 다양성 = NAT 판정 근거 (개수는 len(ua_set))

        "ip_class": head.get("ip_class"),
        "ip_asn": head.get("ip_asn"),
        "ip_org": head.get("ip_org"),
        "ip_country": head.get("ip_country"),
        "is_nat_whitelisted": head.get("is_nat_whitelisted"),

        "is_baseline_eligible": all(g.get("baseline_eligible", True) for g in group),
    }


# === 테스트 ===
if __name__ == "__main__":
    base = {"status": 200, "method": "GET", "bytes_sent": 2400,
            "ip_asn": "AS16509", "ip_org": "AWS", "ip_country": "US"}
    logs = []
    # 윈도우 경계 정렬 시작점 (1778000100 % 300 == 0) — 30건이 한 5분 윈도우에 들도록
    WIN0 = 1778000100
    # S4 공격자: 단일 cloud IP 가 5분 내 30명의 서로 다른 sub 의 /addresses 조회
    for i in range(30):
        logs.append({**base, "client_ip": "13.124.0.9", "ip_class": "cloud",
                     "receive_epoch": WIN0 + i * 8,
                     "uri": f"/api/addresses/14000{i:04d}", "user_id": f"14000{i:04d}",
                     "user_agent": "python-requests/2.31", "baseline_eligible": True})
    # 정상 사용자: 단일 cgnat IP, 본인 sub 만
    for i in range(6):
        logs.append({**base, "client_ip": "118.235.82.230", "ip_class": "cgnat_kr",
                     "ip_country": "KR", "receive_epoch": WIN0 + i * 30,
                     "uri": "/api/products", "user_id": "140000511",
                     "user_agent": "Mozilla/5.0 Safari", "baseline_eligible": True})

    docs = aggregate_ip_events(logs)
    print(f"=== IP 집계 doc {len(docs)}개 (IP 2개 × 윈도우 3개) ===")
    for d in sorted(docs, key=lambda x: (x["target_id"], x["window_size"])):
        print(f"  [{d['target_id']:16}] {d['window_size']:5} req={d['request_count']:3} "
              f"unique_subs={d['unique_subs_count']:3} ua={len(d['ua_set'])} "
              f"suspicious={d['suspicious_uri_count']}")

    atk_5m = next(d for d in docs if d["target_id"] == "13.124.0.9" and d["window_size"] == "5min")
    normal_5m = next(d for d in docs if d["target_id"] == "118.235.82.230" and d["window_size"] == "5min")
    assert atk_5m["unique_subs_count"] == 30, "S4 공격자 unique_subs=30"
    assert normal_5m["unique_subs_count"] == 1, "정상 unique_subs=1"
    assert len(docs) == 6, "IP 2개 × 윈도우 3개 = 6 doc"
    print("\n계약 점검 통과 ✅ (S4 unique_subs=30 / 정상=1)")

    # === Route B — ASN 집계 검증 (S5/S5b 탐지 + KT 정상 FP 없음) ===
    print("\n=== Route B: ASN 집계 ===")
    # S5/S5b: 20개 분산 IP, 전부 같은 ASN(AS20473 Vultr, unknown class), 40명 sub
    s5_logs = [
        {**base, "client_ip": f"45.32.10.{i % 20}", "ip_class": "unknown",
         "ip_asn": "AS20473", "receive_epoch": WIN0 + i * 5,
         "uri": f"/api/addresses/15000{i:04d}", "user_id": f"15000{i:04d}",
         "user_agent": "python-requests/2.31", "baseline_eligible": True}
        for i in range(40)
    ]
    # 정상: KT 200명이 각자 자기 정보 조회 (cgnat_kr → ASN 집계 제외 대상)
    kt_logs = [
        {**base, "client_ip": f"118.235.0.{i % 256}", "ip_class": "cgnat_kr",
         "ip_asn": "AS4766", "ip_country": "KR", "receive_epoch": WIN0 + i,
         "uri": "/api/products", "user_id": f"14000{i:04d}",
         "user_agent": "Mozilla/5.0", "baseline_eligible": True}
        for i in range(200)
    ]

    asn_docs = aggregate_asn_events(s5_logs)
    s5_5m = next(d for d in asn_docs
                 if d["target_id"] == "AS20473" and d["window_size"] == "5min")
    print(f"  S5 분산공격(IP 20개) → ASN doc: target_type={s5_5m['target_type']} "
          f"target={s5_5m['target_id']} unique_subs={s5_5m['unique_subs_count']}")
    assert s5_5m["target_type"] == "asn", "ASN doc target_type=asn"
    assert s5_5m["unique_subs_count"] == 40, "S5 — IP 20개로 흩어도 ASN 1개로 40명 재집결"

    # ★ B6 — FP 검증: KT 200명 정상 → cgnat_kr 이라 ASN doc 자체가 0건
    kt_asn_docs = aggregate_asn_events(kt_logs)
    print(f"  KT 200명 정상 → ASN doc {len(kt_asn_docs)}건 (cgnat_kr 제외 → 채점 대상 없음)")
    assert kt_asn_docs == [], "B6 FP 검증: cgnat_kr 은 ASN 집계 제외 → doc 0건"

    print("\nRoute B 점검 통과 ✅ "
          "(S5 분산 → ASN 재집결 unique_subs=40 / KT 200명 → ASN doc 0 = FP 없음)")
