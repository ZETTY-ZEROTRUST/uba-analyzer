# Kibana 필드·쿼리 치트시트 (Phase 5 패널 빌드용)

> Discover에서 데이터뷰 만들 때, Lens 패널 만들 때 참고. ES에서 실제 확인한 field caps 기준 (2026-05-20).

## 인덱스별 필드 매핑

### `uba-risk-scores-*` (50k+ docs, 알람 후보 334) — **패널 1·6 데이터 소스**

| 필드 | 타입 | 용도 |
|---|---|---|
| `@timestamp` / `computed_at` | date | 시계열 X축 |
| `target_id` | keyword | aggregable — 타깃별 그룹 |
| `target_type` | keyword | `user` / `ip` / `asn` |
| `total_score` | integer | 점수 — 히스토그램·필터 |
| `dominant_factor` | keyword | aggregable — 팩터별 색상 |
| `attacker_level` | keyword | `L0` / `L2` / `L4` / `L4(Slow & Low)` |
| `factor_breakdown.*` | object → integer | F별 점수 (7팩터) |
| `data_exfiltration_detected` | boolean | (현재 항상 false — descope) |
| `window_size` | keyword | `5min` / `1h` / `24h` |
| `ip_class` | keyword | NAT/cloud 분류 |
| `ip_asn` | keyword | ASN 분류 |

### `uba-alerts-*` (33 docs, Phase 3a 알람) — **패널 5·7 데이터 소스**

| 필드 | 타입 | 용도 |
|---|---|---|
| `@timestamp` | date | 알람 발생 시각 |
| `target_id` / `target_type` | keyword | aggregable |
| `total_score` | long | 점수 |
| `dominant_factor` | keyword (+.keyword) | aggregable |
| `attacker_level` | keyword (+.keyword) | aggregable |
| `data_exfiltration_detected` | boolean | |
| `llm_report` | object **(enabled:false)** | _source에서만 표시 — Discover row expand로 한국어 분석문 펴서 보기 |
| `grounding_validation` | object **(enabled:false)** | hallucination_count 등 _source 표시만 |
| `model` / `phase` | text + .keyword | 메타 |

> `llm_report.behavior_analysis` 같은 sub-field로 검색은 안 됨(enabled:false). Discover에서 _source 열어 표시는 OK.

### `uba-baseline-*` (~9 doc/metric) — **패널 3 데이터 소스**

| 필드 | 타입 | 용도 |
|---|---|---|
| `@timestamp` / `computed_at` | date | |
| `factor` | keyword | metric 이름 (`request_burst` / `ip_user_diversity_5min` 등) |
| `p95` / `p99` | float | 분포 통계 |
| `sample_count` | long | baseline 표본 수 |
| `cold_start` | boolean | true면 baseline 미형성 → 시각화에서 회색 처리 권장 |

### `uba-intelligence-*` (1 doc, Phase 3b 캠페인) — **패널 8 데이터 소스**

| 필드 | 타입 | 용도 |
|---|---|---|
| `@timestamp` / `computed_at` | date | |
| `report_type` | keyword | `daily` |
| `model` | text (+.keyword) | `claude-sonnet-4-6` |
| `llm_report` | object **(enabled:false)** | campaigns / cross_campaign_assessment / mitre_mapping / cve_mapping 전체 — Discover row expand |
| `grounding_validation` | object | hallucination_count 0 강조용 |

### `filebeat-*` (119,924 docs) — **원본 로그 (참고용)**

| 필드 | 타입 | 용도 |
|---|---|---|
| `@timestamp` | date | |
| `client_ip` | **ip** | IP 주소 — ES IP 타입 지원 |
| `ip_class` / `ip_asn` | keyword | asn-classify 결과 |
| `jwt.sub` / `jwt.kid` | keyword | JWT 클레임 분해 (Filebeat processor 출력) |

### `mitre-attack` (697 기법) — **grounding 검증 인덱스**

field caps 비어있음 (doc \_id가 T코드 자체 — body는 minimal). Discover에서 `_id: T1110` 식으로 직접 확인.

## 8 패널 데이터뷰·쿼리 매핑

| # | 패널 | 데이터뷰 | 핵심 필드 / KQL |
|---|---|---|---|
| **1** | 리스크 점수 히스토그램 | `uba-risk-scores-*` | X: `total_score` (range agg, bins 0/30/50/70/80/100), Y: count, Filter: `total_score >= 30` |
| **2** | 팩터별 p99 분포 | `uba-baseline-*` | X: `factor` (keyword), Y: `p99` (max), Filter: `cold_start: false` |
| **3** | baseline 시계열 | `uba-baseline-*` | X: `@timestamp`, Y: `p99`, Break: `factor` |
| **4** | 점수 + 알람 추이 | `uba-risk-scores-*` | X: `@timestamp` (5min), Y1: `total_score` max, Y2: count `total_score >= 50` |
| **5** | Top 20 위험 target | `uba-alerts-*` | Table — `target_id` (keyword) terms top 20, Cols: `total_score`, `dominant_factor`, `attacker_level`, `llm_report.behavior_analysis` (✅ display only) |
| **6** | 상위 target 점수 추이 | `uba-risk-scores-*` | X: `@timestamp`, Y: `total_score`, Break: `target_id` top 5, Filter: `total_score >= 50` |
| **7** | Slack 알람 + LLM 리포트 Discover | `uba-alerts-*` | saved search — `dominant_factor: ip_user_diversity` 등 필터 + row expand로 `llm_report` 한국어 분석 |
| **8** | Phase 3b 캠페인 리포트 | `uba-intelligence-*` | Discover 1 doc row expand → `llm_report.campaigns` 펴서 보기 |

## 시연 KQL 쿼리 묶음 (Discover에서 복사)

**S2 victim 확인** — uba-risk-scores-*:
```
target_id: "140000518" and dominant_factor: "token_replay"
```

**S4 IP 확인** — uba-risk-scores-*:
```
target_id: "15.164.10.40" and total_score >= 50
```

**S6 Slow & Low** — uba-risk-scores-*:
```
attacker_level: "L4(Slow & Low)" and target_id: "98.138.10.66"
```

**S7 정상 NAT (알람 0 증거)** — uba-risk-scores-*:
```
target_id: ("175.197.50.12" or "121.135.40.77")
```
→ 결과 전부 score 30, dominant_factor=`ip_user_diversity` 보이면 합격.

**Phase 3b 캠페인 doc 펴보기** — uba-intelligence-*:
```
phase: "3b"
```
→ row expand → llm_report.campaigns 펴서 한국어 분석 캡처.

## 발표 시연 동선 (3분 컷)

1. **uba-risk-scores Discover** — `total_score >= 50` → 334건 알람 후보. dominant_factor 별 색상.
2. **uba-alerts Discover** — `dominant_factor: token_replay` 으로 S2 victim doc 펴서 한국어 behavior_analysis 보여주기.
3. **uba-intelligence Discover** — Phase 3b 캠페인 리포트 펴서 "AI가 6 알람을 2 캠페인으로 묶었다" 시각.
4. **S7 검증** — 정상 NAT KQL → score 30 capped, 알람 0건.
5. **filebeat-* 원본** — S4 IP `15.164.10.40` 필터 → JWT 클레임 분해된 모습 (`jwt.sub`, `jwt.kid` 등).

## 함정 / 주의

- `llm_report` / `grounding_validation`은 **enabled:false** — sub-field로 검색·집계 안 됨. Discover row expand로 본문 봐야 함.
- `factor_breakdown.*`도 strict 매핑 시기 따라 sub-field 분리 안 됐을 수 있음 → Lens에서 안 보이면 데이터뷰 refresh.
- `uba-intelligence`는 1 doc뿐이라 시각화보다 *Discover row expand* 가 본질. 패널 8은 Markdown 패널로 "오늘의 캠페인 리포트 — Discover 링크" 형태가 깔끔.
- 시간대: 인덱스 이름은 UTC (`*-2026.05.19`), 내부 `@timestamp`는 ISO with timezone. Kibana 시간 selector는 KST로 보이게 설정.
