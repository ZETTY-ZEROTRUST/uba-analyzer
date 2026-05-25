#!/usr/bin/env python3
"""Phase 3b orchestrator stdout JSON → ES uba-intelligence 색인 + Slack daily 발송.

orchestrator.run_phase_3b 가 stdout 으로만 JSON dump 하고 ES write/Slack 발송은
누락 (5/16 G-4 의 intelligence_runner 미구현). 이 wrapper 가 그 역할.

사용:
    python scripts/write_intel_doc.py --input /tmp/3b_output.json
    # 또는 stdin 으로
    cat /tmp/3b_output.json | python scripts/write_intel_doc.py
"""
import argparse, json, os, sys, warnings
from datetime import datetime, timezone
from pathlib import Path

warnings.simplefilter('ignore')


def normalize(o):
    """ES mapping 충돌 회피 — 정수형 float → int."""
    if isinstance(o, dict):
        return {k: normalize(v) for k, v in o.items()}
    if isinstance(o, list):
        return [normalize(x) for x in o]
    if isinstance(o, float) and o.is_integer():
        return int(o)
    return o


def load_env(env_path):
    """파일에서 KEY=VAL load → os.environ."""
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        if '=' in line and not line.startswith('#'):
            k, _, v = line.partition('=')
            os.environ[k.strip()] = v.strip()


def build_slack_message(intel):
    """Phase 3b doc → Slack daily 풍부화 메시지 (campaigns + timeline + cross-campaign)."""
    campaigns = intel.get('campaigns') or []
    cx = intel.get('cross_campaign_insights') or {}
    gv = intel.get('grounding_validation') or {}
    meta = intel.get('report_meta') or {}

    lines = [
        f":dart: *ZETI 일일 캠페인 인텔리전스* (Sonnet 4.6, hallucination={gv.get('hallucination_count', 0)})",
        f"분석 기간: {(intel.get('time_range_start') or '')[:19]} ~ {(intel.get('time_range_end') or '')[:19]}",
        f"식별 캠페인: *{len(campaigns)}* / 분석 alerts: {meta.get('alerts_analyzed', '?')}",
    ]
    for c in campaigns[:5]:
        cid = c.get('campaign_id', '?')
        sev = c.get('severity', '?')
        name = c.get('campaign_name', '?')
        ass = (c.get('attacker_assessment') or '')[:400]
        targets = c.get('affected_targets') or {}
        users = (targets.get('users') or [])
        ips = (targets.get('ips') or [])
        mitre = c.get('mitre_techniques') or []
        timeline = c.get('timeline') or []
        recs = c.get('forward_recommendations') or []

        lines += [
            "",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f":rotating_light: *{cid}* [`{sev}`] — {name}",
            f"_{ass}_",
        ]
        if users:
            lines.append(f">*영향 사용자 ({len(users)})*: `" + ", ".join(users[:8]) + "`")
        if ips:
            lines.append(f">*영향 IP ({len(ips)})*: `" + ", ".join(ips[:8]) + "`")
        if mitre:
            mstr = " / ".join(f"`{m.get('id', '?')}` {m.get('name', '')}" for m in mitre[:3])
            lines.append(f">*MITRE*: {mstr}")
        if timeline:
            lines.append(f">*Timeline* ({len(timeline)} events):")
            for ev in timeline[:4]:
                t = (ev.get('event_time') or '')[11:19]
                lines.append(f">  • `{t}` {ev.get('target', '?')} [{ev.get('score', '?')}점] {ev.get('dominant_factor', '?')}")
        if recs:
            lines.append(f">*권고 조치 ({len(recs)})*:")
            for r in recs[:4]:
                lines.append(f">  {r[:180]}")

    if cx:
        lines += [
            "",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f":warning: *[Cross-campaign — `{cx.get('overall_risk', '?')}`]*",
            f"_temporal_overlap_: {(cx.get('temporal_overlap') or '')[:400]}",
            f"_shared_indicators_: {(cx.get('shared_indicators') or '')[:300]}",
        ]
    return "\n".join(lines)


def build_markdown(intel):
    """Phase 3b doc → Kibana 패널 markdown (Slack 메시지와 동등한 정보 풍부도)."""
    campaigns = intel.get('campaigns') or []
    cx = intel.get('cross_campaign_insights') or {}
    gv = intel.get('grounding_validation') or {}
    meta = intel.get('report_meta') or {}
    tr_start = (intel.get('time_range_start') or '')[:19].replace('T', ' ')
    tr_end = (intel.get('time_range_end') or '')[:19].replace('T', ' ')

    md = [
        "## 🛡️ ZETI 일일 캠페인 인텔리전스 (Sonnet 4.6)",
        "",
        f"**분석 기간**: `{tr_start}` ~ `{tr_end}` (UTC)  |  **식별 캠페인**: **{len(campaigns)}**  |  **분석 alerts**: {meta.get('alerts_analyzed', '?')}  |  **hallucination**: `{gv.get('hallucination_count', 0)}`",
        "",
        "---",
        "",
    ]
    for c in campaigns:
        cid = c.get('campaign_id', '?')
        sev = c.get('severity', '?')
        name = c.get('campaign_name', '?')
        ass = c.get('attacker_assessment') or ''
        targets = c.get('affected_targets') or {}
        users = (targets.get('users') or [])
        ips = (targets.get('ips') or [])
        mitre = c.get('mitre_techniques') or []
        timeline = c.get('timeline') or []
        recs = c.get('forward_recommendations') or []
        sev_emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "🔶", "LOW": "ℹ️"}.get(sev, "•")
        md += [f"### {sev_emoji} **{cid}** — {name}  `[{sev}]`", "", f"_{ass}_", ""]
        if mitre:
            mstr = " / ".join(f"`{m.get('id', '?')}` {m.get('name', '')}" for m in mitre)
            md.append(f"- **MITRE**: {mstr}")
        if users:
            md.append(f"- **영향 사용자 ({len(users)})**: `{', '.join(users[:10])}`")
        if ips:
            md.append(f"- **영향 IP ({len(ips)})**: `{', '.join(ips[:10])}`")
        if timeline:
            md.append(f"- **Timeline ({len(timeline)} events)**:")
            for ev in timeline[:6]:
                t = (ev.get('event_time') or '')[11:19]
                md.append(f"  - `{t}` `{ev.get('target', '?')}` [{ev.get('score', '?')}점] {ev.get('dominant_factor', '?')}")
        if recs:
            md.append(f"- **권고 조치**:")
            for i, rec in enumerate(recs[:5], 1):
                md.append(f"  {i}. {rec}")
        md += ["", "---", ""]
    if cx:
        md.append(f"### ⚡ Cross-campaign Insights `[overall_risk: {cx.get('overall_risk', '?')}]`")
        md.append("")
        if cx.get('temporal_overlap'):
            md.append(f"- **temporal_overlap**: {cx['temporal_overlap']}")
        if cx.get('shared_indicators'):
            md.append(f"- **shared_indicators**: {cx['shared_indicators']}")
        md.append("")
    md += ["---", f"_최종 분석: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC  |  Sonnet 4.6 + grounding validator_"]
    return "\n".join(md)


def update_kibana_markdown(intel, kibana_url, auth, viz_id):
    """Kibana visualization markdown 패널 갱신."""
    import requests
    g = requests.get(f"{kibana_url}/api/saved_objects/visualization/{viz_id}", auth=auth)
    if g.status_code != 200:
        print(f'[write_intel] Kibana GET fail: {g.status_code}', file=sys.stderr)
        return False
    vs = json.loads(g.json()['attributes']['visState'])
    if vs.get('type') != 'markdown':
        print(f'[write_intel] Kibana viz not markdown type ({vs.get("type")})', file=sys.stderr)
        return False
    vs['params']['markdown'] = build_markdown(intel)
    r = requests.put(
        f"{kibana_url}/api/saved_objects/visualization/{viz_id}",
        auth=auth,
        headers={'kbn-xsrf': 'true', 'Content-Type': 'application/json'},
        json={"attributes": {"visState": json.dumps(vs, ensure_ascii=False)}},
    )
    print(f'[write_intel] Kibana markdown PUT: {r.status_code}')
    return r.status_code in (200, 201)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', help='Phase 3b orchestrator stdout JSON file (없으면 stdin)')
    ap.add_argument('--env', default='/opt/zeti-uba/.env')
    ap.add_argument('--es-index-prefix', default='uba-intelligence-')
    ap.add_argument('--kibana-url', default='http://10.0.41.10:5601')
    ap.add_argument('--kibana-viz-id', default='uba-p8-daily-intel')
    ap.add_argument('--skip-slack', action='store_true')
    ap.add_argument('--skip-kibana', action='store_true')
    args = ap.parse_args()

    load_env(Path(args.env))

    # input 로드 — file 또는 stdin
    if args.input:
        raw = Path(args.input).read_text(encoding='utf-8')
    else:
        raw = sys.stdin.read()

    # orchestrator stdout 의 마지막 JSON object 추출 (앞에 INFO log 가 있을 수 있음)
    end = raw.rfind('}')
    if end == -1:
        print('ERROR: no closing brace in input', file=sys.stderr)
        return 1
    depth = 0; start = -1
    for i in range(end, -1, -1):
        c = raw[i]
        if c == '}': depth += 1
        elif c == '{': depth -= 1
        if depth == 0:
            start = i; break
    if start == -1:
        print('ERROR: no balanced JSON', file=sys.stderr)
        return 1

    intel = json.loads(raw[start:end + 1])
    # ES metadata fields 제거
    for k in ('_id', '_index', '_score', '_source', '_type'):
        intel.pop(k, None)
    intel = normalize(intel)
    intel.setdefault('@timestamp', datetime.now(timezone.utc).isoformat())
    intel.setdefault('computed_at', datetime.now(timezone.utc).isoformat())

    # ES 색인
    from elasticsearch import Elasticsearch
    es = Elasticsearch(
        os.environ['ES_HOST'],
        api_key=os.environ['UBA_ES_API_KEY'],
        verify_certs=False, ssl_show_warn=False,
    )
    idx = args.es_index_prefix + datetime.now(timezone.utc).strftime('%Y.%m.%d')
    res = es.index(index=idx, document=intel)
    print(f'[write_intel] ES: {res["result"]} _id={res["_id"]} index={idx}')

    # Slack daily 발송
    if not args.skip_slack and os.environ.get('SLACK_WEBHOOK_URL'):
        import requests
        msg = build_slack_message(intel)
        r = requests.post(
            os.environ['SLACK_WEBHOOK_URL'],
            json={'text': msg, 'mrkdwn': True}, timeout=10,
        )
        print(f'[write_intel] Slack: {r.status_code}')

    # Kibana markdown 갱신 — 패널이 자동으로 최신 doc 표시
    if not args.skip_kibana:
        elastic_user = os.environ.get('ES_USER', 'elastic')
        elastic_pass = os.environ.get('ES_PASS', '')
        update_kibana_markdown(
            intel, args.kibana_url, (elastic_user, elastic_pass), args.kibana_viz_id,
        )

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
