#!/usr/bin/env python3
"""Generate the ZETI UBA Kibana 8.19 dashboard saved-objects NDJSON.

Hand-escaping nested visState/searchSource JSON is error-prone, so the
dashboard is built as Python dicts and serialised here.

Output: uba-dashboard.ndjson  (import via Stack Management -> Saved Objects)

Covers panels 3,4,6,7,8 + 4 data views + the dashboard container.
Panels 1,2,5 (Lens) are built in the UI per BUILD_GUIDE.md, then the whole
dashboard is re-exported to overwrite this file.

FIELD-NAME ASSUMPTIONS (no live data existed to verify against — see DEPLOY.md):
  uba-baseline       : @timestamp, factor(keyword), p99(number)
  uba-risk-scores-*  : @timestamp, total_score(number), target_id(keyword)
  uba-alerts-*       : @timestamp, target_id, dominant_factor_korean,
                       total_score, score_delta, throttle_bypass_reason,
                       mitre_mapping, llm_report.behavior_analysis
"""

from __future__ import annotations

import json

CORE = "8.19.0"


def viz(obj_id, title, vis_state, type_mv="8.5.0"):
    """A `visualization` saved object with no index-pattern reference
    (TSVB string-index mode / markdown — both reference-free)."""
    return {
        "id": obj_id,
        "type": "visualization",
        "typeMigrationVersion": type_mv,
        "coreMigrationVersion": CORE,
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state, ensure_ascii=False),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []}
                )
            },
        },
        "references": [],
    }


# --- TSVB helpers ---------------------------------------------------------

def tsvb_series(sid, color, label, metric, chart_type="line", **extra):
    s = {
        "id": sid,
        "color": color,
        "label": label,
        "split_mode": "everything",
        "metrics": [metric],
        "chart_type": chart_type,
        "line_width": 2,
        "point_size": 0,
        "fill": 0 if chart_type == "line" else 0.6,
        "stacked": "none",
        "formatter": "number",
        "axis_position": "left",
        "separate_axis": 0,
    }
    s.update(extra)
    return s


def tsvb(panel_id, title, index_pattern, series):
    return {
        "title": title,
        "type": "metrics",
        "aggs": [],
        "params": {
            "id": panel_id,
            "type": "timeseries",
            "series": series,
            "time_field": "@timestamp",
            "index_pattern": index_pattern,
            "use_kibana_indexes": False,
            "interval": "",
            "axis_position": "left",
            "axis_formatter": "number",
            "axis_scale": "normal",
            "show_grid": 1,
            "show_legend": 1,
            "legend_position": "bottom",
            "tooltip_mode": "show_all",
            "drop_last_bucket": 0,
        },
    }


# --- index patterns (data views) -----------------------------------------

def index_pattern(obj_id, title):
    return {
        "id": obj_id,
        "type": "index-pattern",
        "typeMigrationVersion": "8.0.0",
        "coreMigrationVersion": CORE,
        "attributes": {"title": title, "name": title, "timeFieldName": "@timestamp"},
        "references": [],
    }


objects = []

objects.append(index_pattern("uba-alerts", "uba-alerts-*"))
objects.append(index_pattern("uba-risk-scores", "uba-risk-scores-*"))
objects.append(index_pattern("uba-baseline", "uba-baseline*"))
objects.append(index_pattern("uba-intelligence", "uba-intelligence-*"))


# --- panel 3 — baseline p99 per factor (TSVB) ----------------------------

p3 = tsvb(
    "p3", "패널3 — baseline p99 (팩터별)", "uba-baseline*",
    [tsvb_series(
        "p3s1", "#E7664C", "p99",
        {"id": "p3m1", "type": "avg", "field": "p99"},
        split_mode="terms", terms_field="factor", terms_size=7,
    )],
)
objects.append(viz("uba-p3-baseline", p3["title"], p3))


# --- panel 4 — avg score line + alert-count bars (TSVB, 2 indices) -------

p4 = tsvb(
    "p4", "패널4 — 시간대별 평균 점수 + 알람 수", "uba-risk-scores-*",
    [
        tsvb_series(
            "p4s1", "#6092C0", "평균 total_score",
            {"id": "p4m1", "type": "avg", "field": "total_score"},
        ),
        tsvb_series(
            "p4s2", "#E7664C", "알람 수",
            {"id": "p4m2", "type": "count"},
            chart_type="bar", axis_position="right", separate_axis=1,
            override_index_pattern=1, series_index_pattern="uba-alerts-*",
            series_time_field="@timestamp", series_interval="",
        ),
    ],
)
objects.append(viz("uba-p4-score-alerts", p4["title"], p4))


# --- panel 6 — top-5 risky targets score trajectory (TSVB) ---------------

p6 = tsvb(
    "p6", "패널6 — 상위 위험 target 점수 추이", "uba-risk-scores-*",
    [tsvb_series(
        "p6s1", "#E7664C", "total_score",
        {"id": "p6m1", "type": "avg", "field": "total_score"},
        split_mode="terms", terms_field="target_id", terms_size=5,
        terms_order_by="p6m1", terms_direction="desc",
    )],
)
p6["params"]["filter"] = {"query": "total_score >= 70", "language": "kuery"}
objects.append(viz("uba-p6-top-targets", p6["title"], p6))


# --- panel 8 — daily intelligence report (Markdown) ----------------------

_md = (
    "## ZETI 일일 인텔리전스 리포트\n\n"
    "`uba-intelligence-*` (report_type=daily) 최신 문서를 표시하는 패널.\n\n"
    "- **campaign_summary** — 캠페인 요약\n"
    "- **timeline** — 시간순 이벤트\n"
    "- **attacker_assessment** — 공격자 평가\n"
    "- **pattern_analysis** — S4 / S6 / 미분류\n"
    "- **risk_assessment** — affected_subs, estimated_data_exposure_bytes\n"
    "- **forward_recommendations** — 향후 24h 모니터링 권고\n\n"
    "> 정적 Markdown 패널입니다. 발표 시점에 최신 daily 리포트 본문을 붙여넣거나,\n"
    "> 라이브로 만들려면 BUILD_GUIDE.md의 TSVB-markdown 옵션 참고."
)
p8 = {
    "title": "패널8 — 일일 인텔리전스 리포트",
    "type": "markdown",
    "params": {"markdown": _md, "fontSize": 12, "openLinksInNewTab": True},
    "aggs": [],
}
objects.append(viz("uba-p8-daily-intel", p8["title"], p8))


# --- panel 7 — alerts + LLM report history (Discover saved search) -------

search_source = {
    "query": {"query": "", "language": "kuery"},
    "filter": [],
    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
}
objects.append({
    "id": "uba-p7-alerts",
    "type": "search",
    "typeMigrationVersion": "8.0.0",
    "coreMigrationVersion": CORE,
    "attributes": {
        "title": "패널7 — Slack 알람 + LLM 리포트 이력",
        "description": "",
        "hits": 0,
        "columns": [
            "target_id", "dominant_factor_korean", "total_score", "score_delta",
            "throttle_bypass_reason", "mitre_mapping", "llm_report.behavior_analysis",
        ],
        "sort": [["@timestamp", "desc"]],
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps(search_source)
        },
    },
    "references": [
        {"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
         "type": "index-pattern", "id": "uba-alerts"},
    ],
})


# --- dashboard container -------------------------------------------------

# 48-col grid. panel 4 full width on top, then 3|6, then 7 full, then 8 full.
_layout = [
    ("uba-p4-score-alerts", "visualization", 0, 0, 48, 12),
    ("uba-p3-baseline", "visualization", 0, 12, 24, 13),
    ("uba-p6-top-targets", "visualization", 24, 12, 24, 13),
    ("uba-p7-alerts", "search", 0, 25, 48, 15),
    ("uba-p8-daily-intel", "visualization", 0, 40, 48, 12),
]
panels = []
refs = []
for i, (oid, otype, x, y, w, h) in enumerate(_layout, start=1):
    ref_name = f"panel_{i}"
    panels.append({
        "version": CORE,
        "type": otype,
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
        "panelIndex": str(i),
        "embeddableConfig": {"enhancements": {}},
        "panelRefName": ref_name,
    })
    refs.append({"name": ref_name, "type": otype, "id": oid})

objects.append({
    "id": "uba-soc-dashboard",
    "type": "dashboard",
    "typeMigrationVersion": "8.14.0",
    "coreMigrationVersion": CORE,
    "attributes": {
        "title": "ZETI UBA — SOC 대시보드",
        "description": "멘토 4단계의 2·3단계 시각화. 패널 1·2·5는 BUILD_GUIDE.md로 UI 추가.",
        "panelsJSON": json.dumps(panels, ensure_ascii=False),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "timeRestore": True,
        "timeFrom": "now-24h",
        "timeTo": "now",
        "refreshInterval": {"pause": True, "value": 60000},
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        },
    },
    "references": refs,
})


def main():
    out = "uba-dashboard.ndjson"
    with open(out, "w", encoding="utf-8") as fh:
        for obj in objects:
            fh.write(json.dumps(obj, ensure_ascii=False))
            fh.write("\n")
    print(f"wrote {out}: {len(objects)} saved objects")
    for o in objects:
        print(f"  {o['type']:14} {o['id']}")


if __name__ == "__main__":
    main()
