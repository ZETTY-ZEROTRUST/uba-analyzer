# ZETI UBA — Kibana + Slack 배포 절차

이번 작업 산출물의 배포·적용 가이드. 작성일 2026-05-15.

## 산출물

| 파일 | 용도 | 배포 상태 |
|---|---|---|
| `llm-agent/slack_notifier.py` | Slack Incoming Webhook 전송 (Phase 3a/3b) | ✅ uba-server 배포됨 |
| `infra/es/uba-alerts-mapping-add.json` | §3 추가 필드 매핑 (PUT body) | 미적용 (아래 참고) |
| `infra/kibana/uba-dashboard.ndjson` | Kibana 8.19 대시보드 (패널 3,4,6,7,8) | 미import |
| `infra/kibana/BUILD_GUIDE.md` | Lens 패널 1,2,5 빌드 가이드 | — |
| `infra/kibana/gen-dashboard.py` | NDJSON 생성기 (수정 시 재생성용) | — |
| `mcp/es-mcp/mint-es-key.sh` | es-mcp 읽기전용 키 발급 | ✅ 실행 완료, `.env` 기록됨 |

---

## ⚠️ 선행 조건 — 데이터 파이프라인

2026-05-15 검증 결과, 대시보드가 보는 인덱스가 비어있음:

| 인덱스 | 상태 |
|---|---|
| `logs-zeti-*` | 0건 (원본 로그) |
| `uba-risk-scores-*` | 0건 |
| `uba-baseline` | 인덱스 없음 |
| `uba-intelligence-*` | 0건 |
| `uba-alerts-*` | 19건 (단 v10 아닌 레거시 `U-LLM-IDOR-RECON` 포맷) |

→ **대시보드를 import해도 데이터가 들어오기 전까지 패널은 빈 상태.** 구조는 미리
만들어 두고, factor_engine(룰+z-score) 가동 + Phase 3a/3b 실행으로 데이터가 쌓이면
자동으로 채워짐. NDJSON의 필드명은 스펙/OUTPUT_SCHEMA 기반 **가정**이며, 실제
factor_engine 출력 필드가 다르면 데이터 뷰에서 조정 필요 (아래 표 참고).

레거시 `uba-alerts-2026.05.06` 19건은 v10 패널에 안 잡힘(필드 없음). 발표 전
깔끔하게 하려면 `DELETE uba-alerts-2026.05.06` 고려.

### NDJSON 가정 필드명

| 인덱스 | 가정 필드 |
|---|---|
| `uba-baseline` | `@timestamp`, `factor`(keyword), `p99` |
| `uba-risk-scores-*` | `@timestamp`, `total_score`, `target_id`(keyword) |
| `uba-alerts-*` | `@timestamp`, `target_id`, `dominant_factor_korean`, `total_score`, `score_delta`, `throttle_bypass_reason`, `mitre_mapping`, `llm_report.behavior_analysis` |

---

## 1. Slack Webhook

`slack_notifier.py`는 환경변수에서 Webhook URL을 읽음:

- `SLACK_WEBHOOK_URL` (필수) — Phase 3a 실시간 알람 채널
- `SLACK_WEBHOOK_URL_DAILY` (선택) — Phase 3b 일일 리포트 채널 (없으면 위 URL로 폴백)

Slack 워크스페이스에서 Incoming Webhook을 만든 뒤, ReAct 루프 오케스트레이터의
환경(예: systemd unit `Environment=` 또는 `/opt/zeti-uba/llm-agent/.env`)에 주입.
**Webhook URL은 시크릿** — repo/챗에 넣지 말 것.

호출:
```python
from slack_notifier import send_realtime_alert, send_daily_report
send_realtime_alert(alert_doc)      # Phase 3a — uba-alerts 문서 전달
send_daily_report(intelligence_doc) # Phase 3b daily — uba-intelligence 문서 전달
```

---

## 2. §3 ES 매핑 추가

`uba-alerts-mapping-add.json` 은 v10 `uba-alerts` 에 4개 필드를 추가:
`llm_report.behavior_analysis_korean`, `dominant_factor_korean`,
`dominant_factor_alias`, `nat_judgment{}`.

**적용 시점**: 스펙대로 Phase 3a 진입 직전. v10 `uba-alerts` 인덱스/템플릿이
존재해야 함 (현재 미존재).

읽기전용 es-mcp 키로는 안 됨 (`manage` 권한 필요). elastic 자격증명으로:
```bash
# 기존 인덱스에 적용
curl -k -u elastic:PW -X PUT "https://10.0.41.10:9200/uba-alerts-*/_mapping" \
  -H 'Content-Type: application/json' \
  --data-binary @infra/es/uba-alerts-mapping-add.json

# 미래 날짜 인덱스용 — uba-alerts 인덱스 템플릿에도 동일 properties 병합
curl -k -u elastic:PW "https://10.0.41.10:9200/_index_template/*uba-alert*"  # 현재 템플릿 확인 후 갱신
```
`dynamic=strict` 이어도 properties 추가 병합은 호환됨.

---

## 3. Kibana 대시보드 import

1. Kibana(8.19) → **Stack Management → Saved Objects → Import**
2. `infra/kibana/uba-dashboard.ndjson` 선택 → import
   - 생성 객체: 데이터 뷰 4 + TSVB 3 + Markdown 1 + saved search 1 + 대시보드 1
3. `BUILD_GUIDE.md` 대로 Lens 패널 1·2·5 를 대시보드에 추가
4. 대시보드 저장 → Saved Objects 에서 대시보드 re-export(✅ include related) →
   `uba-dashboard.ndjson` 덮어쓰기

> TSVB 패널이 import 후 깨지면(8.19 스키마 드리프트) `gen-dashboard.py` 수정 후
> 재생성하거나 해당 패널만 TSVB UI에서 재작성.

---

## 4. es-mcp 읽기전용 키 — 알려진 제약

`mint-es-key.sh` 로 발급한 `uba-mcp` 키는 `_search`/`_mapping`/`_count`/
`_field_caps` 는 되지만 **`_cat/indices` 가 403**. `server.py` 의 `list_indices`
툴이 `_es.cat.indices()` 를 쓰므로 런타임에 실패함.

해결안 (둘 중 하나):
- `list_indices` 를 `GET <pattern>/_mapping` 키 나열로 교체 (cat 의존 제거), 또는
- 키 재발급 시 role_descriptor 에 인덱스 레벨 `monitor` 추가.

`query_elasticsearch` (ReAct 루프 주 사용 툴)는 `_search` 기반이라 영향 없음.

---

## 5. 샘플 데이터로 대시보드 미리보기

실데이터가 없을 때 대시보드 렌더링을 확인하는 용도. `infra/es/load-sample-data.py`
가 4개 `*-sample` 인덱스(`uba-risk-scores-sample`, `uba-baseline-sample`,
`uba-alerts-sample`, `uba-intelligence-sample`)에 합성 값을 적재. **`logs-zeti-*`
미접촉, factor_engine 미실행** — 순수 미리보기용 목업. 데이터뷰가 와일드카드
(`uba-risk-scores-*` / `uba-baseline*` / ...)라 자동 매칭됨.

실행 (uba-server, 대화형):
```
aws ssm start-session --target i-0e06820c477644613
python3 /opt/zeti-uba/infra/es/load-sample-data.py    # elastic 비밀번호 입력
```

Kibana 접속 (별도 터미널, 세션 유지):
```
aws ssm start-session --target i-09634c7f2a6fe739b \
  --document-name AWS-StartPortForwardingSession \
  --parameters "portNumber=5601,localPortNumber=5601"
```
→ 브라우저 `http://localhost:5601` → `uba-dashboard.ndjson` import → 대시보드 확인.

미리보기 끝나면 정리:
```
curl -k -u elastic:PW -X DELETE "https://10.0.41.10:9200/\
uba-risk-scores-sample,uba-baseline-sample,uba-alerts-sample,uba-intelligence-sample"
```
