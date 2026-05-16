"""
attacker_level_classifier.py — Phase 2: 공격자 등급 분류 + 데이터 유출 플래그

factor_engine 의 risk doc(factor_breakdown + dominant_factor)을 받아 공격자 등급과
데이터 유출 플래그를 덧붙인다.

설계 의도:
  - 공격자 등급은 dominant_factor 로 정한다 — "무엇이 이 타깃을 위험하게 만들었나"가
    곧 "공격자가 어떤 능력을 가졌나"의 신호다:
      · token_replay 지배   → L2: 정상 토큰을 도용/하이재킹. 위조 능력은 미확인.
      · ip_user_diversity / cumulative_exfil 지배 → L4: 한 IP 가 다수 sub 를 건드림
        = 서명키 보유로 토큰을 다수 위조한 외부 공격자.
  - 등급 라벨은 phase_3a LLM 스키마 enum 과 1:1 — {L0, L2, L4, L4(Slow & Low)}.
    LLM 이 이 값을 그대로 받으므로 enum 을 벗어나면 안 된다.
  - response_sensitivity 는 등급을 정하지 않는다 (PROGRESS: 응답민감도는 별개 차원).
    데이터 유출은 "등급"이 아니라 별도 플래그(data_exfiltration_detected)로 표현 —
    L2 든 L4 든 유출은 일어날 수 있으므로 차원을 분리한다.
  - 24h 윈도우의 ip_user_diversity / cumulative_exfil → "L4(Slow & Low)" (저속 장기 유출).
"""

# phase_3a OUTPUT_SCHEMA.attacker_level enum — 이 4값만 허용
ATTACKER_LEVELS = ("L0", "L2", "L4", "L4(Slow & Low)")

# 등급 결정에 쓰지 않는 팩터 (PROGRESS: 응답민감도는 등급 결정 안 함)
_LEVEL_NEUTRAL = {"response_sensitivity"}


def _secondary_factor(factor_breakdown):
    """response_sensitivity 를 뺀 나머지 중 점수 최대 팩터 (>0). 없으면 None."""
    candidates = {k: v for k, v in factor_breakdown.items()
                  if k not in _LEVEL_NEUTRAL and v > 0}
    if not candidates:
        return None
    return max(candidates, key=candidates.get)


def classify_attacker_level(factor_breakdown, dominant_factor, target_type=None, window_size=None):
    """factor_breakdown + dominant → 공격자 등급 (ATTACKER_LEVELS 중 하나)."""
    dom = dominant_factor
    if dom is None:
        return "L0"   # 점수 0 = 정상

    # 응답민감도가 dominant 면 등급은 secondary 팩터로 재판정
    if dom == "response_sensitivity":
        dom = _secondary_factor(factor_breakdown)
        if dom is None:
            return "L4"   # 응답민감도 단독 고득점 = 대량 데이터 수집 = 키 보유 추정

    if dom == "ip_user_diversity":
        return "L4(Slow & Low)" if window_size == "24h" else "L4"
    if dom == "cumulative_exfil":
        return "L4(Slow & Low)"   # 누적 유출 = 저속 장기 = Slow & Low
    if dom == "token_replay":
        return "L2"               # 토큰 하이재킹 — 도용, 위조 능력 미확인
    if dom == "token_violation":
        return "L2"               # 규격 위반 토큰 사용 — 도용/변조 의심
    if dom in ("request_burst", "response_size_burst"):
        return "L2"               # 통계 보조 팩터 단독 — 약한 신호, 보수적으로 L2
    return "L0"


def detect_exfiltration(factor_breakdown):
    """factor_breakdown → 데이터 유출 플래그 (등급과 별개 차원).

    response_sensitivity 점수 기반 (factor_engine 가중표: 70 = 확정 / 50 = 의심).
    """
    rs = factor_breakdown.get("response_sensitivity", 0)
    return {
        "data_exfiltration_detected": rs >= 70,
        "suspected_exfiltration": 50 <= rs < 70,
    }


def classify(risk_doc, target_type=None, window_size=None):
    """factor_engine risk doc 에 attacker_level + 유출 플래그를 채워 넣는다 (in-place).

    target_type/window_size 는 risk_doc 에 있으면 거기서 읽는다.
    """
    fb = risk_doc["factor_breakdown"]
    tt = target_type or risk_doc.get("target_type")
    ws = window_size or risk_doc.get("window_size")

    risk_doc["attacker_level"] = classify_attacker_level(
        fb, risk_doc.get("dominant_factor"), tt, ws)
    exfil = detect_exfiltration(fb)
    risk_doc["data_exfiltration_detected"] = exfil["data_exfiltration_detected"]
    risk_doc["suspected_exfiltration"] = exfil["suspected_exfiltration"]
    return risk_doc


# === 테스트 ===
if __name__ == "__main__":
    def fb(**kw):
        base = {k: 0 for k in ("token_violation", "request_burst", "token_replay",
                               "response_size_burst", "ip_user_diversity",
                               "response_sensitivity", "cumulative_exfil")}
        base.update(kw)
        return base

    cases = [
        # (factor_breakdown, dominant, window, 기대 등급, 설명)
        (fb(), None, "5min", "L0", "정상"),
        (fb(token_replay=80), "token_replay", "5min", "L2", "S2 하이재킹"),
        (fb(ip_user_diversity=70), "ip_user_diversity", "5min", "L4", "S4 enumeration"),
        (fb(ip_user_diversity=100), "ip_user_diversity", "24h", "L4(Slow & Low)", "S6 24h"),
        (fb(cumulative_exfil=50), "cumulative_exfil", "24h", "L4(Slow & Low)", "누적 유출"),
        (fb(response_sensitivity=70, token_replay=80), "response_sensitivity", "5min", "L2",
         "응답민감도 dominant → secondary(token_replay) 재판정"),
    ]
    for breakdown, dom, win, expected, desc in cases:
        got = classify_attacker_level(breakdown, dom, "user", win)
        status = "OK" if got == expected else "FAIL"
        print(f"  [{status}] {desc:42} → {got}")
        assert got == expected, f"{desc}: {got} != {expected}"
        assert got in ATTACKER_LEVELS, f"enum 위반: {got}"

    print()
    ex_hi = detect_exfiltration(fb(response_sensitivity=70))
    ex_mid = detect_exfiltration(fb(response_sensitivity=50))
    ex_no = detect_exfiltration(fb())
    print(f"  exfil rs=70: {ex_hi}")
    print(f"  exfil rs=50: {ex_mid}")
    assert ex_hi["data_exfiltration_detected"] and not ex_hi["suspected_exfiltration"]
    assert ex_mid["suspected_exfiltration"] and not ex_mid["data_exfiltration_detected"]
    assert not ex_no["data_exfiltration_detected"] and not ex_no["suspected_exfiltration"]

    # classify() in-place 보강
    doc = {"factor_breakdown": fb(ip_user_diversity=100), "dominant_factor": "ip_user_diversity",
           "target_type": "ip", "window_size": "24h"}
    classify(doc)
    assert doc["attacker_level"] == "L4(Slow & Low)"
    print(f"\n  classify() 보강: attacker_level={doc['attacker_level']}")
    print("\n계약 점검 통과 ✅ (등급 enum 정합 + 유출 플래그 차원 분리)")
