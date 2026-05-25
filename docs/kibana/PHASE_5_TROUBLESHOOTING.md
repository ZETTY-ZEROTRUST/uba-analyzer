# Phase 5 — Kibana 패널 빌드 / 임포트 트러블슈팅

발견 시점: 2026-05-24 (저녁). D-0 데이터 (정상 baseline + AMBIG_NAT) 상태에서 `uba-dashboard.ndjson` import 후 첫 검토.

대시보드: **"ZETI UBA — SOC 대시보드"** (`uba-soc-dashboard`).

---

## 공통 — 첫 점검 (반드시 먼저)

### ❶ 시간 범위 (대부분 "No results" 의 원인)

Kibana default time picker = **"Last 15 minutes"**. 우리 데이터는 `2026-05-22 ~ 2026-05-24` 라 *전부 안 보임*.

**해결**:
- 대시보드 우측 상단 시간 picker → **"Last 7 days"** 또는
- Absolute: `2026-05-22 00:00` ~ `2026-05-24 23:59:59`

대시보드 전체 5 패널이 *동시* 갱신됨.

### ❷ 데이터뷰 패턴 (5-3 단계 점검 사항)

`Stack Management → Data Views → uba-baseline` 의 title 이 `uba-baseline*` (별 1 개) 로 박혀있음. 인덱스명은 `uba-baseline-2026.05.24` 라 매치되긴 하지만 *비표준*.

**해결**: title 을 `uba-baseline-*` (별 + dash) 로 수정.

---

## 패널별 증상 + 원인 + 해결

### 패널 3 — baseline p99 (팩터별) → ❌ **다단 정합성 버그**

**원인 두 가지가 겹쳐 있음**:

#### 원인 1 — 필드명 mismatch (`factor` vs `metric`)
- `FIELD_CHEATSHEET.md` 표기: `factor | keyword | metric 이름`
- **실제 baseline doc 의 필드명** (`uba-baseline-2026.05.24` 의 _source 직접 확인): `metric`
  ```json
  {
    "sample_count": 11222, "mean": 9.437, "std": 8.176,
    "p50": 7.0, "p95": 26.0, "p99": 36.0,
    "metric": "request_burst",     // ← 패널 3 이 찾는 "factor" 가 아님
    "computed_at": "...", "cold_start": false
  }
  ```
- ndjson 의 패널 3 정의가 *옛 schema (`factor`)* 가정 → 현재 코드는 `metric` 저장 → mismatch.

#### 원인 2 — 시간 필드 mismatch (★ 더 중요)
- `uba-baseline` 데이터뷰의 `timeFieldName = @timestamp` (ndjson 정의).
- 그런데 *baseline doc 에 `@timestamp` 필드 자체가 없음*. `computed_at` 만 있음.
- Kibana 가 모든 9 doc 을 *시간 미할당* 으로 처리 → **시간 필터 적용 시 0 결과**.
- 패널 3 의 필드를 `metric` 으로 바꿨는데도 "No results found" 가 뜬 *진짜 이유*.

→ *4 데이터뷰 (uba-alerts/risk-scores/baseline/intelligence) 모두 timeFieldName=@timestamp 박힌 상태인데*, baseline doc 만 그 필드 없음. spec ↔ code ↔ data 3-layer 미동기.

**해결 (순서)**:

**Step A (즉시) — 데이터뷰 의 Time field 변경**:
1. `Stack Management → Data Views → uba-baseline` 클릭
2. "Edit data view" (또는 우측 ⋯)
3. Timestamp field 드롭다운: `@timestamp` → **`computed_at`** 변경
4. 또는 "I don't want to use the time filter" 선택 (더 깔끔 — baseline 은 시계열 X, 분포 statistics)
5. Save → 9 doc 즉시 보임

**Step B (UI) — 패널 3 의 필드 갱신**:
1. 대시보드 → 패널 3 우측 위 ⋮ → "Edit visualization"
2. X 축 의 필드: `factor` 또는 `factor.keyword` → **`metric`** 또는 **`metric.keyword`** 로 변경
3. Save → Save visualization → Dashboard Save

**Step C (코드 root fix, G 후속)** — `baseline_store.py`:
- doc 박을 때 `@timestamp` 같이 박음 (`computed_at` 과 동일 값):
  ```python
  doc = {
      "@timestamp": computed_at,    # ★ 추가 — Kibana data view 기본 timeField
      "computed_at": computed_at,
      "metric": metric_name,
      # ...
  }
  ```
- 다음 D-2 pipeline 부터 영구 해결. 기존 9 doc 은 *backfill 필요* (또는 단순히 다음 pipeline 으로 덮어쓰기).
- (선택) `metric` 외에 `factor` 별칭도 박으면 ndjson 수정 안 해도 됨 — 하지만 *별칭 두 개* 보다 *spec 통일* 이 깔끔.

---

### 패널 4 — 시간대별 평균 점수 + 알람 수 → ❌ **"No results found"**

**원인 1 (가장 흔함)**: 시간 범위 = "Last 15 minutes" 라 데이터 안 보임.

**해결**: 위 ❶ 시간 범위 fix 적용.

**원인 2 (시간 fix 후에도 안 나오면)**: 데이터뷰의 timestamp 필드 mismatch. risk-doc 의 `@timestamp` vs `computed_at` 필드 차이.
- risk-scores doc 은 `@timestamp` + `computed_at` 둘 다 있음
- 패널이 default `@timestamp` 쓸 텐데 그 필드가 *risk-doc 의 window_start* 와 동기됐는지 확인 필요

**진단**: Discover 에서 `uba-risk-scores-*` 데이터뷰 + Last 7 days → 44,886 doc 보이면 정상. 안 보이면 timestamp 필드 mismatch.

---

### 패널 6 — 상위 위험 target 점수 추이 → ⚠️ **"그래프 이상하게 보임"**

**원인 후보** (구체 화면 못 봄, 추정):
1. **데이터 분포 자체의 multimodal discrete**: total_score 가 0/30/70/100 양자화. 시계열 line chart 가 *점만 찍히고 line 없는* 형태로 보일 수 있음. 정상 동작이지만 직관적이지 않음.
2. **target_id 분리 안 됨**: Top 20 target 의 *각각* line 이 아닌 *합산 line 1 개* 로 보이면 breakdown 필드 (`target_id`) 미적용.
3. **시간 윈도우 너무 좁음**: 시간 picker default 15min 이라 *한 점만 찍힘*.

**해결**:
1. 위 ❶ 시간 범위 먼저 (Last 7 days)
2. 패널 Edit → Breakdown 에 `target_id` (Top N=20) 추가 확인
3. Y 축 max → score (max 또는 percentile_95) 인지 확인 — sum 이면 비정상적으로 큰 값 (모든 윈도우 합)

---

### 패널 7 — Slack 알람 + LLM 리포트 이력 → ❌ **"No results found"**

**원인**: `uba-alerts-*` 인덱스 **자체가 ES 에 없음**.
- 이번 D-0 pipeline 은 Phase 2 (factor 채점 + risk-scores 저장) 까지만. Phase 3a (Haiku 4.5 LLM 알람) 미실행.
- LLM 안 돌면 uba-alerts-* 인덱스 안 만들어짐. 패널 7 의 search 가 *없는 인덱스* 를 query → No results.

**해결**: 정상 동작. Phase 3a LLM 실행되면 자동 채워짐.
- D-2 후 + 별도 명령으로 Phase 3a trigger 가능: `python3 -m llm-agent.phase3a_poller --alert-threshold 50 --window 168h` (코드 위치 확인 후 정확한 명령)
- 발표 시연용으로는 **D-2 후 LLM trigger** 가 필수 단계.

---

### 패널 8 — 일일 인텔리전스 리포트 → 미확인 (No results 추정)

**원인**: `uba-intelligence-*` 인덱스 없음. Phase 3b (Sonnet 4.6 캠페인 인텔리전스) 미실행.

**해결**: 패널 7 과 동일 패턴. Phase 3b trigger 시 채워짐.
- D-2 + Phase 3a + Phase 3b 순서 (Phase 3b 가 Phase 3a 의 알람을 묶음).

---

## 빠진 3 패널 (UI 빌드 필요)

PROGRESS_TODO Phase 5 의 *8 패널 목표* 중 ndjson 에 4 visualization 만. 사용자 UI 작업으로 추가:

| 패널 | 데이터 소스 | Lens 설정 |
|---|---|---|
| **패널 1 — 리스크 점수 히스토그램** | `uba-risk-scores-*` | x=`total_score` interval=10, y=count, breakdown=`ip_class` 또는 `target_type` |
| **패널 2 — 팩터별 p95/p99 분포** | `uba-baseline-*` | x=`metric.keyword` (★ `factor` 아님), y=`p99` (max), breakdown=`window_size` if available |
| **패널 5 — Top 20 target + LLM 리포트** | `uba-alerts-*` 또는 fallback `uba-risk-scores-*` | table: target_id / total_score / dominant_factor / (alerts 인덱스 있으면) `llm_report.behavior_analysis` 컬럼 |

---

## D-2 후 다시 점검할 항목

- **시나리오 알람**: D-2 후 risk-scores 에 attack-* 알람 추가 → 패널 4/6 의 시계열 spike 보임 (S2/S4/S6 시간대).
- **uba-alerts-* 인덱스**: LLM trigger 후 33+ 알람 (PROGRESS_DONE 2026-05-20 기준 33건, 이번엔 더 추가 가능) → 패널 7 채워짐.
- **uba-intelligence-* 인덱스**: Phase 3b trigger 후 1+ 캠페인 doc → 패널 8 채워짐.

---

## 정합성 정리할 항목 (G 의 자질구레로 흡수)

1. **`metric` vs `factor` schema 통일** — FIELD_CHEATSHEET 수정 또는 baseline_store 가 두 필드 다 박음. 발표 후 reconcile.
2. **uba-baseline 데이터뷰 패턴 수정** (`uba-baseline*` → `uba-baseline-*`).
3. **uba-dashboard.ndjson re-export** — UI 에서 패널 수정 + 패널 1/2/5 추가 후 export 해서 git 에 박음 (5-7 단계).
4. **`filebeat-*` 데이터뷰 추가** (선택) — JWT/IP raw 데이터 시각화 시 필요.
