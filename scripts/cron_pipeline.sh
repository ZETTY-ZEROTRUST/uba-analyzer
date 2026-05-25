#!/bin/bash
# cron: UBA pipeline 매 5분 — uba-events/baseline/risk-scores 갱신 (baseline 재사용).
# crontab entry: */5 * * * * /opt/zeti-uba/scripts/cron_pipeline.sh
set -e
cd /opt/zeti-uba
set -a; [ -f .env ] && source .env; set +a
TS=$(date +%Y%m%d_%H%M%S)
.venv/bin/python3 pipeline.py --hours 1 --no-baseline 2>&1 \
  | tee -a logs/cron_pipeline.log \
  | tail -3
echo "--- $TS done (exit=$?) ---" >> logs/cron_pipeline.log
