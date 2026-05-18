"""risk_doc_adapter.py — uba-risk-scores risk doc → Phase 3a alert 입력 변환.

factor_engine/risk_scorer 가 ES `uba-risk-scores` 에 넣는 risk doc 의 필드명과
phase_3a.build_user_prompt() 가 기대하는 alert dict 의 키가 다르다. 이 어댑터가
그 사이를 잇는다 — Phase 2(채점)와 Phase 3a(LLM 분석)의 인터페이스 경계.

risk doc (입력)                         alert (phase_3a 입력)
--------------------------------------  ----------------------------------
target_type / target_id                 그대로
window_size                             window
total_score / dominant_factor           그대로 (dominant_factor = v12 영문 키)
factor_breakdown {7 키}                  그대로
attacker_level / data_exfiltration_*     그대로
ip_class/ip_asn/ip_org/ip_country/...    ip_context {...} 로 묶음
ip_user_diversity_meta                   그대로 (user doc 엔 없음 → None)
evidence.token_replay                    sample_logs 에 증거로 합류 (있으면)
"""

from __future__ import annotations

from typing import Any


def risk_doc_to_alert(risk_doc: dict[str, Any],
                      sample_logs: list[dict[str, Any]] | None = None,
                      p99_today: float | None = None) -> dict[str, Any]:
    """uba-risk-scores risk doc → phase_3a build_user_prompt 입력 alert dict.

    Args:
        risk_doc: factor_engine/risk_scorer 출력 (attacker_level_classifier.classify
                  까지 거친 완성 risk doc).
        sample_logs: 직전 로그 dict 리스트 (react_agent 가 ES 에서 미리 조회해 trim).
                     None 이면 token_replay 증거만이라도 넣는다.

    Returns:
        phase_3a.build_user_prompt() 가 그대로 받는 alert dict.
    """
    samples = list(sample_logs or [])

    # user doc 의 token_replay 증거는 ip 메타가 없으므로 sample_logs 에 정황으로 합류
    evidence = risk_doc.get("evidence") or {}
    tr = evidence.get("token_replay") or {}
    for vs in (tr.get("violating_samples") or [])[:3]:
        samples.append({
            "_evidence": "token_replay_crossing",
            "jti": vs.get("jti"),
            "ip_class_set": vs.get("ip_class_set"),
            "ip_country_set": vs.get("ip_country_set"),
            "crossing_type": vs.get("crossing_type"),
        })

    meta = risk_doc.get("ip_user_diversity_meta") or {}
    return {
        "target_type": risk_doc.get("target_type"),
        "target_id": risk_doc.get("target_id"),
        "total_score": risk_doc.get("total_score", 0),
        "p99_today": p99_today,                              # throttle score floor 보조
        "dominant_factor": risk_doc.get("dominant_factor"),
        "attacker_level": risk_doc.get("attacker_level", "L0"),
        "data_exfiltration_detected": risk_doc.get("data_exfiltration_detected", False),
        "window": risk_doc.get("window_size"),
        "window_size_f9": risk_doc.get("window_size"),       # phase_3a _factor_table F9 행
        "soft_cap_applied": bool(meta.get("capped", False)),
        # ★ 출력 키 = factor_scores — orchestrator/throttle/phase_3a 가 이 이름으로 읽음.
        #   risk doc 의 factor_breakdown(v12 영문 키) 을 키 이름만 바꿔 담는다.
        "factor_scores": risk_doc.get("factor_breakdown", {}),
        "ip_context": {
            "ip_class": risk_doc.get("ip_class"),
            "ip_asn": risk_doc.get("ip_asn"),
            "ip_org": risk_doc.get("ip_org"),
            "ip_country": risk_doc.get("ip_country"),
            "is_nat_whitelisted": risk_doc.get("is_nat_whitelisted"),
        },
        "ip_user_diversity_meta": risk_doc.get("ip_user_diversity_meta"),
        "sample_logs": samples[:8],
    }


# === 테스트 ===
if __name__ == "__main__":
    # S4 ip risk doc (factor_engine.score_ip_window + attacker_level_classifier.classify 출력 형태)
    s4_risk = {
        "target_type": "ip", "target_id": "13.124.0.9",
        "window_start": "2026-05-16T09:00:00Z", "window_size": "5min",
        "total_score": 70, "dominant_factor": "ip_user_diversity",
        "factor_breakdown": {"token_violation": 0, "request_burst": 0, "token_replay": 0,
            "response_size_burst": 0, "ip_user_diversity": 70, "response_sensitivity": 0,
            "cumulative_exfil": 0},
        "attacker_level": "L4", "data_exfiltration_detected": False,
        "suspected_exfiltration": False,
        "ip_user_diversity_meta": {"raw_score": 70, "capped": False, "unique_subs_raw": 100},
        "ip_class": "cloud", "ip_asn": "AS16509", "ip_org": "AWS", "ip_country": "US",
        "is_nat_whitelisted": False,
    }
    a = risk_doc_to_alert(s4_risk, p99_today=62)
    assert a["window"] == "5min" and a["dominant_factor"] == "ip_user_diversity"
    assert a["ip_context"]["ip_class"] == "cloud"
    assert a["ip_user_diversity_meta"]["unique_subs_raw"] == 100
    assert a["factor_scores"]["ip_user_diversity"] == 70, "출력키 factor_scores (v12 키 보존)"
    assert "factor_breakdown" not in a, "factor_breakdown → factor_scores 로 이름 변경됨"
    assert a["p99_today"] == 62 and a["window_size_f9"] == "5min"
    print(f"S4 ip → alert: window={a['window']} dom={a['dominant_factor']} "
          f"ip_class={a['ip_context']['ip_class']}")

    # S2 user risk doc — token_replay 증거가 sample_logs 로
    s2_risk = {
        "target_type": "user", "target_id": "140000007",
        "window_size": "5min", "total_score": 80, "dominant_factor": "token_replay",
        "factor_breakdown": {"token_violation": 0, "request_burst": 0, "token_replay": 80,
            "response_size_burst": 0, "ip_user_diversity": 0, "response_sensitivity": 0,
            "cumulative_exfil": 0},
        "attacker_level": "L2", "data_exfiltration_detected": False,
        "evidence": {"token_replay": {"jti_count_with_class_crossing": 1,
            "violating_samples": [{"jti": "j-1", "ip_class_set": ["cgnat_kr", "cloud"],
                "ip_country_set": ["KR", "US"], "crossing_type": "ip_class"}]}},
    }
    a2 = risk_doc_to_alert(s2_risk)
    assert a2["dominant_factor"] == "token_replay" and a2["attacker_level"] == "L2"
    assert any(s.get("_evidence") == "token_replay_crossing" for s in a2["sample_logs"])
    print(f"S2 user → alert: dom={a2['dominant_factor']} level={a2['attacker_level']} "
          f"증거 샘플 {len(a2['sample_logs'])}건")
    print("risk_doc_adapter 검증 통과 ✅")
