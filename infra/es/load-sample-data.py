#!/usr/bin/env python3
"""ZETI UBA — load synthetic sample data so the Kibana dashboard renders.

Writes fabricated OUTPUT-side values into four *-sample indices:
    uba-risk-scores-sample, uba-baseline-sample,
    uba-alerts-sample, uba-intelligence-sample

It does NOT touch logs-zeti-* and does NOT run factor_engine. This is mock
data for previewing dashboard panels only — every doc carries `sample: true`.
The dashboard data views (uba-risk-scores-*, uba-alerts-*, uba-intelligence-*,
uba-baseline*) match these by wildcard.

Run INTERACTIVELY on the UBA server (reaches ES):
    aws ssm start-session --target i-0e06820c477644613
    python3 /opt/zeti-uba/infra/es/load-sample-data.py
The elastic password is read with getpass — never echoed or logged.

Cleanup after preview:
    curl -k -u elastic:PW -X DELETE "https://10.0.41.10:9200/\
uba-risk-scores-sample,uba-baseline-sample,uba-alerts-sample,uba-intelligence-sample"
"""

from __future__ import annotations

import getpass
import json
import random
import sys
from datetime import datetime, timedelta, timezone

import requests
import urllib3

urllib3.disable_warnings()

ES = "https://10.0.41.10:9200"
random.seed(20260515)

FACTORS = {
    "F2": "토큰규격위반", "F3": "요청수급증", "F6": "토큰공유",
    "F7": "응답크기급증", "F9": "IP-사용자다양성",
    "F_Resp": "응답민감도", "F_Cum": "누적유출량",
}
STAT_FACTORS = ["F3", "F7", "F9", "F_Cum"]
MITRE = {
    "F2": [("T1078", "Valid Accounts")],
    "F3": [("T1110", "Brute Force")],
    "F6": [("T1550", "Use Alternate Authentication Material")],
    "F7": [("T1530", "Data from Cloud Storage")],
    "F9": [("T1606.001", "Web Cookies"), ("T1110", "Brute Force")],
    "F_Resp": [("T1041", "Exfiltration Over C2 Channel")],
    "F_Cum": [("T1041", "Exfiltration Over C2 Channel"),
              ("T1567", "Exfiltration Over Web Service")],
}
BEHAVIOR = {
    "F9": "단일 IP에서 5분간 {n}명의 서로 다른 user ID로 /api/addresses를 호출. "
          "IP-사용자다양성 z-score가 baseline을 200 이상 초과. KMS 검증과 Spring "
          "Security @PreAuthorize를 모두 통과한 정상 서명 토큰.",
    "F_Resp": "{tid} 대상이 1시간 동안 민감 엔드포인트(/api/users/*)를 반복 호출. "
              "응답민감도 점수가 baseline p99를 크게 상회.",
    "F_Cum": "{tid}에서 24시간 누적 응답 바이트가 정상 분포를 이탈. 누적유출량 "
             "신호가 저속·은닉형(Slow & Low) 패턴으로 지속됨.",
    "F2": "{tid}의 토큰 서명 규격이 비정상. 토큰규격위반 신호 — 위조·변조 서명 의심.",
    "F3": "{tid}에서 단시간 요청 수가 급증. 요청수급증 — 자동화된 enumeration 정황.",
    "F6": "동일 토큰이 다수 IP에서 교대로 사용됨. 토큰공유 — 토큰 탈취·공유 의심.",
    "F7": "{tid}의 응답 크기가 급격히 증가. 응답크기급증 — 대량 데이터 조회 정황.",
}

now = datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat()


# --- ES session -----------------------------------------------------------

pw = getpass.getpass("elastic 비밀번호: ")
S = requests.Session()
S.auth = ("elastic", pw)
S.verify = False
try:
    r = S.get(ES, timeout=10)
except Exception as exc:  # noqa: BLE001
    print("ERROR: ES 연결 실패:", exc)
    sys.exit(1)
if r.status_code != 200:
    print("ERROR: elastic 인증 실패 HTTP", r.status_code)
    sys.exit(1)
print("elastic 인증 OK")


def recreate(name: str, props: dict) -> None:
    S.delete(f"{ES}/{name}", timeout=30)
    r = S.put(f"{ES}/{name}", json={"mappings": {"properties": props}}, timeout=30)
    if r.status_code not in (200, 201):
        print(f"ERROR: {name} 생성 실패:", r.status_code, r.text[:300])
        sys.exit(1)
    print(f"  index 생성: {name}")


def bulk(name: str, docs: list[dict]) -> None:
    lines = []
    for d in docs:
        lines.append('{"index":{}}')
        lines.append(json.dumps(d, ensure_ascii=False))
    body = ("\n".join(lines) + "\n").encode("utf-8")
    r = S.post(f"{ES}/{name}/_bulk", data=body,
               headers={"Content-Type": "application/x-ndjson"}, timeout=120)
    j = r.json()
    if j.get("errors"):
        for it in j.get("items", []):
            res = next(iter(it.values()))
            if res.get("error"):
                print(f"  WARN {name} bulk error:", json.dumps(res["error"])[:200])
                break
    S.post(f"{ES}/{name}/_refresh", timeout=30)
    print(f"  loaded {len(docs)} docs -> {name}")


# --- targets --------------------------------------------------------------

targets = [("ip", f"203.0.113.{10 + i}") for i in range(18)]
targets += [("user", f"140002{100 + i}") for i in range(8)]

fcodes = list(FACTORS)
profiles: dict[str, tuple[str, str]] = {}
for idx, (_tt, tid) in enumerate(targets):
    if idx % 9 == 0:
        prof = "high"
    elif idx % 3 == 0:
        prof = "susp"
    else:
        prof = "normal"
    profiles[tid] = (prof, fcodes[idx % len(fcodes)])


# --- 1. uba-risk-scores-sample -------------------------------------------

recreate("uba-risk-scores-sample", {
    "@timestamp": {"type": "date"},
    "target_type": {"type": "keyword"},
    "target_id": {"type": "keyword"},
    "total_score": {"type": "integer"},
    "factor_scores": {"properties": {f: {"type": "integer"} for f in FACTORS}},
    "sample": {"type": "boolean"},
})
rs_docs = []
for h in range(24):
    t = now - timedelta(hours=23 - h)
    for tt, tid in targets:
        prof, dom = profiles[tid]
        if prof == "normal":
            score = random.randint(3, 27)
        elif prof == "susp":
            score = random.randint(32, 66)
        else:  # high — ramps up over the 24h window
            score = max(0, min(100, int(55 + (h / 23) * 40) + random.randint(-5, 5)))
        fs = {f: random.randint(0, 18) for f in FACTORS}
        fs[dom] = max(fs[dom], score - random.randint(0, 8))
        rs_docs.append({
            "@timestamp": iso(t), "target_type": tt, "target_id": tid,
            "total_score": score, "factor_scores": fs, "sample": True,
        })
bulk("uba-risk-scores-sample", rs_docs)


# --- 2. uba-baseline-sample ----------------------------------------------

recreate("uba-baseline-sample", {
    "@timestamp": {"type": "date"},
    "factor": {"type": "keyword"},
    "factor_korean": {"type": "keyword"},
    "p50": {"type": "float"}, "p95": {"type": "float"}, "p99": {"type": "float"},
    "sample": {"type": "boolean"},
})
scale = {"F3": 12.0, "F7": 80000.0, "F9": 1.2, "F_Cum": 250000.0}
bl_docs = []
for h in range(24):
    t = now - timedelta(hours=23 - h)
    for f in STAT_FACTORS:
        p50 = scale[f] * (1 + random.uniform(-0.15, 0.15))
        p95 = p50 * random.uniform(2.0, 2.8)
        p99 = p95 * random.uniform(1.3, 1.8)
        bl_docs.append({
            "@timestamp": iso(t), "factor": f, "factor_korean": FACTORS[f],
            "p50": round(p50, 2), "p95": round(p95, 2), "p99": round(p99, 2),
            "sample": True,
        })
bulk("uba-baseline-sample", bl_docs)


# --- 3. uba-alerts-sample (v10 schema) -----------------------------------

recreate("uba-alerts-sample", {
    "@timestamp": {"type": "date"},
    "target_type": {"type": "keyword"},
    "target_id": {"type": "keyword"},
    "total_score": {"type": "integer"},
    "score_delta": {"type": "integer"},
    "dominant_factor": {"type": "keyword"},
    "dominant_factor_korean": {"type": "keyword"},
    "dominant_factor_alias": {"type": "keyword"},
    "attacker_level": {"type": "keyword"},
    "data_exfiltration_detected": {"type": "boolean"},
    "window": {"type": "keyword"},
    "throttle_bypass_reason": {"type": "keyword"},
    "mitre_mapping": {"properties": {
        "id": {"type": "keyword"}, "name": {"type": "keyword"},
        "rationale": {"type": "text"}}},
    "nat_judgment": {"properties": {
        "applicable": {"type": "boolean"}, "verdict": {"type": "keyword"},
        "rationale": {"type": "text"}}},
    "llm_report": {"properties": {
        "behavior_analysis": {"type": "text"},
        "behavior_analysis_korean": {"type": "text"}}},
    "sample": {"type": "boolean"},
})
alert_pool = [(tt, tid) for tt, tid in targets if profiles[tid][0] in ("high", "susp")]
random.shuffle(alert_pool)
bypass = [None, "score_jump", "override_factor", "data_exfil_flip"]
al_docs = []
for i in range(18):
    tt, tid = alert_pool[i % len(alert_pool)]
    dom = profiles[tid][1]
    t = now - timedelta(hours=random.randint(0, 23), minutes=random.randint(0, 59))
    score = random.randint(72, 100)
    exfil = dom in ("F_Resp", "F_Cum") or random.random() < 0.25
    level = "L4" if dom in ("F9", "F6", "F_Resp", "F_Cum") else random.choice(["L2", "L4"])
    window = "5분" if dom in ("F9", "F3") else "1시간"
    nsubs = random.randint(80, 340)
    text = BEHAVIOR[dom].format(n=nsubs, tid=tid)
    al_docs.append({
        "@timestamp": iso(t), "target_type": tt, "target_id": tid,
        "total_score": score, "score_delta": random.randint(8, 45),
        "dominant_factor": dom, "dominant_factor_korean": FACTORS[dom],
        "dominant_factor_alias": dom,
        "attacker_level": level, "data_exfiltration_detected": exfil,
        "window": window, "throttle_bypass_reason": random.choice(bypass),
        "mitre_mapping": [
            {"id": mid, "name": mn, "rationale": f"{FACTORS[dom]} 신호와 일치"}
            for mid, mn in MITRE[dom]
        ],
        "nat_judgment": {
            "applicable": dom == "F9",
            "verdict": "attack" if dom == "F9" else "n/a",
            "rationale": "NAT 화이트리스트 미해당 — 공격으로 판정" if dom == "F9" else "",
        },
        "llm_report": {"behavior_analysis": text, "behavior_analysis_korean": text},
        "sample": True,
    })
bulk("uba-alerts-sample", al_docs)


# --- 4. uba-intelligence-sample ------------------------------------------

recreate("uba-intelligence-sample", {
    "@timestamp": {"type": "date"},
    "report_type": {"type": "keyword"},
    "time_range_start": {"type": "date"},
    "time_range_end": {"type": "date"},
    "campaign_summary": {"type": "text"},
    "attacker_assessment": {"type": "text"},
    "pattern_analysis": {"type": "keyword"},
    "timeline": {"properties": {
        "timestamp": {"type": "date"}, "event": {"type": "text"}}},
    "risk_assessment": {"properties": {
        "affected_subs": {"type": "integer"},
        "estimated_data_exposure_bytes": {"type": "long"}}},
    "forward_recommendations": {"type": "text"},
    "sample": {"type": "boolean"},
})
bulk("uba-intelligence-sample", [{
    "@timestamp": iso(now),
    "report_type": "daily",
    "time_range_start": iso(now - timedelta(hours=24)),
    "time_range_end": iso(now),
    "campaign_summary": "지난 24시간 동안 외부 IP 대역(203.0.113.0/24)에서 유효 서명 "
                        "토큰을 사용한 대규모 enumeration 캠페인이 관측됨. 토큰공유 → "
                        "IP-사용자다양성 → 응답민감도/누적유출량으로 전이.",
    "attacker_assessment": "공격자는 유효 서명 토큰을 보유한 L4 등급. KMS·Spring "
                           "Security 검증을 통과하는 정상 토큰으로 IDOR/enumeration 수행.",
    "pattern_analysis": "S4",
    "timeline": [
        {"timestamp": iso(now - timedelta(hours=20)),
         "event": "203.0.113.10 토큰공유 신호 첫 발생"},
        {"timestamp": iso(now - timedelta(hours=14)),
         "event": "IP-사용자다양성 급증 — enumeration 본격화"},
        {"timestamp": iso(now - timedelta(hours=6)),
         "event": "응답민감도·누적유출량으로 전이 — 데이터 수집 단계 진입"},
    ],
    "risk_assessment": {"affected_subs": 312, "estimated_data_exposure_bytes": 327680},
    "forward_recommendations": [
        "203.0.113.0/24 대역 WAF 차단 검토",
        "KMS 서명키 회전 (alias/jwt-signing-key-external)",
        "영향 sub 312명 통지 검토",
    ],
    "sample": True,
}])

print("\n완료. SSM 포트포워딩으로 Kibana 접속 -> uba-dashboard.ndjson import 후 확인.")
print("정리: DELETE uba-risk-scores-sample,uba-baseline-sample,"
      "uba-alerts-sample,uba-intelligence-sample")
