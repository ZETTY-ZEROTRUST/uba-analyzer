#!/bin/bash
# cron: Phase 3a Haiku ReAct 매 5분 — uba-alerts + Slack 실시간 알람.
# crontab entry: 2-59/5 * * * * /opt/zeti-uba/scripts/cron_phase3a.sh
# (pipeline 1분 offset 으로 risk-scores 박힌 후 trigger)
set -e
cd /opt/zeti-uba
set -a; [ -f .env ] && source .env; set +a
TS=$(date +%Y%m%d_%H%M%S)
.venv/bin/python3 llm-agent/phase3a_poller.py --since 10 2>&1 \
  | tee -a logs/cron_phase3a.log \
  | tail -3
echo "--- $TS done ---" >> logs/cron_phase3a.log
