#!/bin/bash
# cron: Phase 3b Sonnet 4.6 캠페인 인텔리전스 매시간.
# crontab entry: 30 * * * * /opt/zeti-uba/scripts/cron_phase3b.sh
#
# 흐름: build_3b_bundle → orchestrator --phase 3b → write_intel_doc
#       (ES 색인 + Slack daily + Kibana markdown 갱신 통합)
set -e
cd /opt/zeti-uba
set -a; [ -f .env ] && source .env; set +a
TS=$(date +%Y%m%d_%H%M%S)
BUNDLE=/tmp/3b_bundle_$TS.json
OUTPUT=/tmp/3b_output_$TS.json

# 1. uba-alerts/risk-scores fetch → bundle JSON
.venv/bin/python3 scripts/build_3b_bundle.py --hours 24 --output "$BUNDLE" 2>&1 \
  | tee -a logs/cron_phase3b.log

# 2. Sonnet 4.6 ReAct → stdout JSON
.venv/bin/python3 llm-agent/orchestrator.py --phase 3b --input "$BUNDLE" \
  > "$OUTPUT" 2>> logs/cron_phase3b.log

# 3. ES 색인 + Slack daily + Kibana markdown PUT
.venv/bin/python3 scripts/write_intel_doc.py --input "$OUTPUT" 2>&1 \
  | tee -a logs/cron_phase3b.log

# cleanup (보존: 최근 5)
ls -1t /tmp/3b_bundle_*.json 2>/dev/null | tail -n +6 | xargs -r rm
ls -1t /tmp/3b_output_*.json 2>/dev/null | tail -n +6 | xargs -r rm

echo "--- $TS done ---" >> logs/cron_phase3b.log
