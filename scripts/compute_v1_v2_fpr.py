#!/usr/bin/env python3
"""
compute_v1_v2_fpr.py — 자기-개선 서사 #2 (NAT 과탐 → soft cap) 의 정량 검증.

v1 (가상, cap 미도입) = ip_user_diversity_meta.raw_score 그대로 채점
v2 (실제, cap 도입)   = total_score

비교 방법 B: pipeline 한 번만 돌리고, 같은 risk-doc 안의 두 컬럼을 동시 추출.
factor_engine.py 수정 없이 v1 시뮬레이션.

코호트 분류 (target_id 기준):
- attack-S{2,4,5,5b,6,8} : attack-simulation/results/*.jsonl 에서 추출한 victim_sub / src_ip
- AMBIG_NAT             : src_ip == 104.196.45.77 (controlled experiment 대조군)
- cgnat_kr              : ip_class == "cgnat_kr" (정상 KR 캐리어 NAT)
- other                 : 위 어디에도 안 잡히는 정상 트래픽

출력:
- FPR 매트릭스 (코호트 × v1/v2)
- TPR 매트릭스 (공격 시나리오별, doc 단위 + target 단위)
- PNG 그래프: v1 vs v2 FPR + 코호트별 stacked
- JSON 덤프: docs/kpi/v1_v2_raw.json (재현용)
"""
import os, sys, json, glob, argparse
from pathlib import Path
from collections import defaultdict
from datetime import datetime, UTC

from dotenv import load_dotenv
from elasticsearch import Elasticsearch, helpers

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
load_dotenv(_ROOT / ".env")

ALERT_THRESHOLD = 50  # scoring/risk_scorer.py 와 동일
AMBIG_NAT_IP = "104.196.45.77"
ATTACK_RESULTS_GLOB = str(_ROOT.parent / "attack-simulation" / "results" / "s*_*.jsonl")


def get_es():
    return Elasticsearch(
        os.environ["ES_HOST"],
        basic_auth=(os.environ["ES_USER"], os.environ["ES_PASS"]),
        verify_certs=False,
        ssl_show_warn=False,
    )


def load_attack_ground_truth(date_prefix="20260524"):
    """attack-simulation jsonl 에서 시나리오별 victim_sub / src_ip 추출."""
    scenarios = {}   # {"S2": {"subs": set, "ips": set}}
    for path in sorted(glob.glob(ATTACK_RESULTS_GLOB)):
        name = Path(path).name
        if date_prefix not in name:
            continue
        scen = name.split("_")[0].upper()
        s = scenarios.setdefault(scen, {"subs": set(), "ips": set(), "doc_count": 0})
        with open(path) as f:
            for line in f:
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if d.get("victim_sub"):
                    s["subs"].add(str(d["victim_sub"]))
                if d.get("src_ip") and d["src_ip"] != "-":
                    s["ips"].add(d["src_ip"])
                s["doc_count"] += 1
    return scenarios


def build_classifier(scenarios):
    """target_id (sub 또는 IP 또는 ASN) → 코호트 이름.

    한 sub/IP 가 여러 시나리오 풀에 속하면 (S5/S5b 처럼 풀 동일) 모든 매칭
    시나리오를 묶어 "attack-S5+S5B" 형식으로 반환 — setdefault 충돌 회피.
    """
    sub_to_scen = defaultdict(set)
    ip_to_scen = defaultdict(set)
    for scen, s in scenarios.items():
        for sub in s["subs"]:
            sub_to_scen[sub].add(scen)
        for ip in s["ips"]:
            ip_to_scen[ip].add(scen)

    def classify(doc):
        target_type = doc.get("target_type")
        target_id = str(doc.get("target_id", ""))
        ip_class = doc.get("ip_class")

        matched = set()
        if target_type == "user":
            matched = sub_to_scen.get(target_id, set())
        elif target_type in ("ip", "asn"):
            matched = ip_to_scen.get(target_id, set())

        if matched:
            return "attack-" + "+".join(sorted(matched))
        if target_id == AMBIG_NAT_IP:
            return "AMBIG_NAT"
        if ip_class == "cgnat_kr":
            return "cgnat_kr"
        if ip_class == "cloud":
            return "cloud-other"
        return "other"

    return classify, sub_to_scen, ip_to_scen


def extract_scores(doc):
    """v1, v2 점수 추출.

    user-윈도우는 cap 무관 (cap 은 ip_user_diversity 전용) → v1=v2.
    ip/asn-윈도우는 ip_user_diversity_meta.raw_score 가 있으면 그게 v1,
    total_score 가 v2.
    """
    v2 = int(doc.get("total_score") or 0)
    meta = doc.get("ip_user_diversity_meta") or {}
    raw = meta.get("raw_score")
    if raw is None:
        return v2, v2
    fb = doc.get("factor_breakdown") or {}
    iud_v2 = int(fb.get("ip_user_diversity") or 0)
    iud_v1 = int(raw)
    # combine 의 재현: override = max(iud, response_sensitivity); deterministic + 0.3*stat
    rs = int(fb.get("response_sensitivity") or 0)
    deterministic = (int(fb.get("token_violation") or 0)
                     + int(fb.get("token_replay") or 0))
    statistical = (int(fb.get("request_burst") or 0)
                   + int(fb.get("response_size_burst") or 0)
                   + int(fb.get("cumulative_exfil") or 0))
    additive = deterministic + 0.3 * statistical
    v1 = min(100, round(max(max(iud_v1, rs), additive)))
    return v1, v2


def fetch_all_risk_docs(es):
    body = {
        "_source": ["target_type", "target_id", "total_score", "ip_class",
                    "ip_user_diversity_meta", "factor_breakdown", "window_size"],
        "query": {"match_all": {}},
    }
    return list(helpers.scan(es, index="uba-risk-scores-*", query=body, size=2000))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--date-prefix", default="20260524", help="attack-sim jsonl 날짜 prefix")
    ap.add_argument("--out-json", default=str(_ROOT / "docs" / "kpi" / "v1_v2_raw.json"))
    ap.add_argument("--out-md", default=str(_ROOT / "docs" / "kpi" / "fpr.md"))
    ap.add_argument("--out-png", default=str(_ROOT / "docs" / "kpi" / "figures" / "v1_v2_fpr.png"))
    args = ap.parse_args()

    scenarios = load_attack_ground_truth(args.date_prefix)
    print(f"[GT] 공격 시나리오: {len(scenarios)}")
    for scen, s in scenarios.items():
        print(f"     {scen}: subs={len(s['subs'])} ips={len(s['ips'])} docs={s['doc_count']}")

    classify, sub_to_scen, ip_to_scen = build_classifier(scenarios)
    es = get_es()
    print("[ES] fetching uba-risk-scores-* ...")
    docs = fetch_all_risk_docs(es)
    print(f"[ES] {len(docs)} risk docs")

    # 코호트 × (v1 알람 / v2 알람 / 총 윈도우)
    matrix = defaultdict(lambda: {"v1_alarms": 0, "v2_alarms": 0, "total": 0,
                                   "v1_scores": [], "v2_scores": []})
    # 시나리오별 binary trigger (PROGRESS_TODO 의 KPI 정의 = "탐지된 시나리오 / 전체")
    scen_status = {scen: {"triggered_v1": False, "triggered_v2": False,
                           "max_v1": 0, "max_v2": 0,
                           "alarm_windows_v1": 0, "alarm_windows_v2": 0,
                           "total_windows": 0, "dominant_factors": defaultdict(int)}
                    for scen in scenarios}
    for hit in docs:
        d = hit["_source"]
        cohort = classify(d)
        v1, v2 = extract_scores(d)
        m = matrix[cohort]
        m["total"] += 1
        m["v1_scores"].append(v1)
        m["v2_scores"].append(v2)
        if v1 >= ALERT_THRESHOLD: m["v1_alarms"] += 1
        if v2 >= ALERT_THRESHOLD: m["v2_alarms"] += 1

        # per-scenario aggregation (한 doc 이 여러 시나리오에 매핑 가능)
        target_type = d.get("target_type")
        target_id = str(d.get("target_id", ""))
        matched = set()
        if target_type == "user":
            matched = sub_to_scen.get(target_id, set())
        elif target_type in ("ip", "asn"):
            matched = ip_to_scen.get(target_id, set())
        for scen in matched:
            s = scen_status[scen]
            s["total_windows"] += 1
            s["max_v1"] = max(s["max_v1"], v1)
            s["max_v2"] = max(s["max_v2"], v2)
            if v1 >= ALERT_THRESHOLD:
                s["triggered_v1"] = True
                s["alarm_windows_v1"] += 1
            if v2 >= ALERT_THRESHOLD:
                s["triggered_v2"] = True
                s["alarm_windows_v2"] += 1
                df = d.get("dominant_factor")
                if df: s["dominant_factors"][df] += 1

    # 출력 — 한국어 표
    print(f"\n{'='*100}\nv1 vs v2 매트릭스 (ALERT_THRESHOLD = {ALERT_THRESHOLD})\n{'='*100}")
    print(f"{'코호트':<22}{'총 윈도우':>10}{'v1 알람':>10}{'v2 알람':>10}{'v1 FPR/TPR':>14}{'v2 FPR/TPR':>14}{'개선(Δ)':>10}")
    print("-" * 100)

    normal_cohorts = ["cgnat_kr", "AMBIG_NAT", "cloud-other", "other"]
    attack_cohorts = sorted([k for k in matrix if k.startswith("attack-")])
    rows = []
    for cohort in normal_cohorts + attack_cohorts:
        m = matrix.get(cohort)
        if not m or m["total"] == 0:
            continue
        v1r = m["v1_alarms"] / m["total"] * 100
        v2r = m["v2_alarms"] / m["total"] * 100
        delta = v1r - v2r
        is_attack = cohort.startswith("attack-")
        rate_label = "TPR" if is_attack else "FPR"
        print(f"{cohort:<22}{m['total']:>10}{m['v1_alarms']:>10}{m['v2_alarms']:>10}"
              f"{v1r:>10.3f}% {v2r:>10.3f}% {delta:>+9.3f}p")
        rows.append({
            "cohort": cohort, "kind": "attack" if is_attack else "normal",
            "rate_label": rate_label, "total": m["total"],
            "v1_alarms": m["v1_alarms"], "v2_alarms": m["v2_alarms"],
            "v1_rate_pct": v1r, "v2_rate_pct": v2r, "delta_pp": delta,
        })

    # Aggregate FPR (정상 코호트 통합)
    normal_total = sum(matrix[c]["total"] for c in normal_cohorts if c in matrix)
    normal_v1 = sum(matrix[c]["v1_alarms"] for c in normal_cohorts if c in matrix)
    normal_v2 = sum(matrix[c]["v2_alarms"] for c in normal_cohorts if c in matrix)
    overall_v1_fpr = normal_v1 / normal_total * 100 if normal_total else 0
    overall_v2_fpr = normal_v2 / normal_total * 100 if normal_total else 0
    print("-" * 100)
    print(f"{'전체 정상 (FPR)':<22}{normal_total:>10}{normal_v1:>10}{normal_v2:>10}"
          f"{overall_v1_fpr:>10.3f}% {overall_v2_fpr:>10.3f}% {overall_v1_fpr-overall_v2_fpr:>+9.3f}p")

    # === per-scenario TPR (시나리오 단위 binary trigger) ===
    print(f"\n{'='*100}\n시나리오 매트릭스 (per-scenario, KPI 정의 = 탐지된 시나리오 / 전체)\n{'='*100}")
    print(f"{'시나리오':<12}{'윈도우':>8}{'v1 탐지':>10}{'v2 탐지':>10}{'max_v1':>10}{'max_v2':>10}{'알람 win v2':>14}{'dominant_factor':>20}")
    print("-" * 100)
    scen_rows = []
    for scen in sorted(scen_status.keys()):
        s = scen_status[scen]
        df_top = max(s["dominant_factors"].items(), key=lambda x: x[1])[0] if s["dominant_factors"] else "—"
        print(f"{scen:<12}{s['total_windows']:>8}"
              f"{('✅' if s['triggered_v1'] else '❌'):>10}"
              f"{('✅' if s['triggered_v2'] else '❌'):>10}"
              f"{s['max_v1']:>10}{s['max_v2']:>10}{s['alarm_windows_v2']:>14}{df_top:>20}")
        scen_rows.append({
            "scenario": scen, "total_windows": s["total_windows"],
            "triggered_v1": s["triggered_v1"], "triggered_v2": s["triggered_v2"],
            "max_v1": s["max_v1"], "max_v2": s["max_v2"],
            "alarm_windows_v1": s["alarm_windows_v1"],
            "alarm_windows_v2": s["alarm_windows_v2"],
            "dominant_factors": dict(s["dominant_factors"]),
        })
    detected_v1 = sum(1 for s in scen_status.values() if s["triggered_v1"])
    detected_v2 = sum(1 for s in scen_status.values() if s["triggered_v2"])
    total_scen = len(scen_status)
    tpr_v1 = detected_v1 / total_scen * 100 if total_scen else 0
    tpr_v2 = detected_v2 / total_scen * 100 if total_scen else 0
    print("-" * 100)
    print(f"{'TPR (시나리오)':<12}{'':>8}{f'{detected_v1}/{total_scen}':>10}{f'{detected_v2}/{total_scen}':>10}"
          f"{'':>10}{'':>10}{tpr_v1:>10.1f}% v1{tpr_v2:>9.1f}% v2")

    # JSON 덤프
    Path(args.out_json).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out_json, "w") as f:
        json.dump({
            "computed_at": datetime.now(UTC).isoformat(),
            "alert_threshold": ALERT_THRESHOLD,
            "ambig_nat_ip": AMBIG_NAT_IP,
            "ground_truth_scenarios": {k: {"subs": sorted(v["subs"]),
                                            "ips": sorted(v["ips"]),
                                            "doc_count": v["doc_count"]}
                                        for k, v in scenarios.items()},
            "matrix": rows,
            "overall": {
                "normal_total": normal_total,
                "v1_fpr_pct": overall_v1_fpr,
                "v2_fpr_pct": overall_v2_fpr,
                "delta_pp": overall_v1_fpr - overall_v2_fpr,
            },
            "scenarios_matrix": scen_rows,
            "tpr": {
                "detected_v1": detected_v1, "detected_v2": detected_v2,
                "total": total_scen, "v1_pct": tpr_v1, "v2_pct": tpr_v2,
            },
        }, f, ensure_ascii=False, indent=2)
    print(f"\n[OUT] JSON: {args.out_json}")

    # Markdown 표 (docs/kpi/fpr.md)
    Path(args.out_md).parent.mkdir(parents=True, exist_ok=True)
    md = [f"# FPR / TPR 매트릭스 (v1 vs v2)",
          f"",
          f"- 알람 threshold = `{ALERT_THRESHOLD}`",
          f"- v1 = soft cap 미도입 가정 (`ip_user_diversity_meta.raw_score` 그대로 채점)",
          f"- v2 = soft cap 도입 (실제 `total_score`)",
          f"- 측정 시각: {datetime.now(UTC).isoformat()}",
          f"",
          f"| 코호트 | 종류 | 총 윈도우 | v1 알람 | v2 알람 | v1 비율 | v2 비율 | Δ (pp) |",
          f"|---|---|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        md.append(f"| `{r['cohort']}` | {r['rate_label']} | {r['total']} "
                  f"| {r['v1_alarms']} | {r['v2_alarms']} "
                  f"| {r['v1_rate_pct']:.3f}% | {r['v2_rate_pct']:.3f}% "
                  f"| {r['delta_pp']:+.3f}p |")
    md.append("")
    md.append(f"## 전체 정상 FPR")
    md.append(f"- v1 FPR = **{overall_v1_fpr:.3f}%** ({normal_v1}/{normal_total})")
    md.append(f"- v2 FPR = **{overall_v2_fpr:.3f}%** ({normal_v2}/{normal_total})")
    md.append(f"- Δ = **{overall_v1_fpr-overall_v2_fpr:+.3f}pp** (soft cap 효과)")
    md.append("")
    md.append(f"## 시나리오 매트릭스 (per-scenario TPR)")
    md.append("")
    md.append("| 시나리오 | 윈도우 | v1 탐지 | v2 탐지 | max_v1 | max_v2 | 알람 win (v2) | dominant_factor |")
    md.append("|---|---:|:---:|:---:|---:|---:|---:|---|")
    for r in scen_rows:
        df_top = max(r["dominant_factors"].items(), key=lambda x: x[1])[0] if r["dominant_factors"] else "—"
        md.append(f"| `{r['scenario']}` | {r['total_windows']} "
                  f"| {'✅' if r['triggered_v1'] else '❌'} "
                  f"| {'✅' if r['triggered_v2'] else '❌'} "
                  f"| {r['max_v1']} | {r['max_v2']} | {r['alarm_windows_v2']} | `{df_top}` |")
    md.append("")
    md.append(f"**TPR (시나리오 단위)**: v1 = **{tpr_v1:.1f}%** ({detected_v1}/{total_scen}) / v2 = **{tpr_v2:.1f}%** ({detected_v2}/{total_scen})")
    Path(args.out_md).write_text("\n".join(md))
    print(f"[OUT] Markdown: {args.out_md}")

    # PNG: v1 vs v2 FPR 코호트별
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np

        labels = [r["cohort"] for r in rows]
        v1_vals = [r["v1_rate_pct"] for r in rows]
        v2_vals = [r["v2_rate_pct"] for r in rows]
        x = np.arange(len(labels))
        w = 0.38

        fig, ax = plt.subplots(figsize=(max(11, len(labels) * 1.2), 6))
        b1 = ax.bar(x - w/2, v1_vals, w, label="v1 (no cap, hypothetical)", color="#c0392b", edgecolor="black")
        b2 = ax.bar(x + w/2, v2_vals, w, label="v2 (soft cap)", color="#27ae60", edgecolor="black")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=30, ha="right")
        ax.set_ylabel("alarm rate (%)  -  FPR for normal, TPR for attack")
        ax.set_title(f"v1 vs v2  alarm rate by cohort  (threshold={ALERT_THRESHOLD})", fontsize=12)
        ax.grid(axis="y", alpha=0.3)
        ax.legend(loc="upper right")
        for b, v in list(zip(b1, v1_vals)) + list(zip(b2, v2_vals)):
            if v > 0:
                ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1.5,
                        f"{v:.1f}%", ha="center", fontsize=8)
        plt.tight_layout()
        Path(args.out_png).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(args.out_png, dpi=130, bbox_inches="tight", facecolor="white")
        print(f"[OUT] PNG: {args.out_png}")
    except ImportError:
        print("[WARN] matplotlib unavailable — PNG skipped")


if __name__ == "__main__":
    main()
