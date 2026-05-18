# ZETI UBA — Kibana 대시보드 빌드 가이드

Kibana **8.19.14** 기준. 8패널 대시보드 = 축1 분포도 4개 + 축2 집중뷰 4개.

- 패널 3·4·6·7·8 → `uba-dashboard.ndjson` import (Stack Management → Saved Objects → Import)
- **패널 1·2·5 (Lens) → 이 문서대로 UI에서 빌드** (Lens saved object는 손으로 쓰면 깨져서 가이드로 분리)

빌드 순서: ① NDJSON import → ② 아래 Lens 패널 3개를 같은 대시보드에 추가 → ③ 대시보드 저장 →
④ Saved Objects에서 대시보드 + 의존 객체 전체 re-export 떠서 `uba-dashboard.ndjson` 덮어쓰기 (reproducibility).

---

## 0. 데이터 뷰 (사전 준비)

NDJSON import 시 4개 데이터 뷰가 함께 생성됨:

| 데이터 뷰 | 인덱스 패턴 | time field |
|---|---|---|
| uba-alerts | `uba-alerts-*` | `@timestamp` |
| uba-risk-scores | `uba-risk-scores-*` | `@timestamp` |
| uba-baseline | `uba-baseline` | `@timestamp` |
| uba-intelligence | `uba-intelligence-*` | `@timestamp` |

> **필드명 검증 필수.** 아래 패널은 `total_score`, `target_type`, `@timestamp` 등
> 필드명을 가정함. import 직후 각 데이터 뷰의 필드 목록과 대조할 것
> (검증 커맨드는 `DEPLOY.md` 참고). 다르면 그 자리에서 다른 필드 선택.

---

## 패널 1 — 사용자/IP별 risk score 분포 (Lens, 멘토 2단계)

위험도 점수가 전체적으로 어떻게 분포하는지. "상위 N개만 봐도 된다"는 메시지.

1. **Visualize → Create → Lens**, 데이터 뷰 = `uba-risk-scores`.
2. 차트 타입 = **Bar vertical**.
3. **Horizontal axis**: `total_score`
   - 함수 = **Intervals** (히스토그램), Granularity / interval = **10** → 0~100 구간 bin 10개.
4. **Vertical axis**: 함수 = **Count of records** → target 수.
5. **Breakdown**: `target_type`
   - 함수 = **Top values**, size = 2 (user / ip) → 두 색 시리즈로 분할.
6. **점수 구간 색대 표현** (Lens 막대는 X값 기준 자동 색대가 없음):
   - 방법 A (권장): Settings → **Reference lines** 레이어 추가, 수직선 X=30, X=70.
     30 왼쪽=정상 / 30~70=의심 / 70+=고위험 영역을 시각적으로 구분.
   - 방법 B: breakdown을 `target_type` 대신 **Filters** 함수로 바꿔 3개 KQL 필터
     (`total_score < 30` 회색 / `total_score >= 30 and total_score < 70` 노랑 /
     `total_score >= 70` 빨강) 각각 색 지정. 이 경우 target_type 분할은 포기.
   - 발표에서 S7 검증을 강조하려면 **방법 B + 필터에 `ip_class` 조건 추가**해
     cgnat_kr IP가 회색 구간에만 있는지 한눈에 보이게 함 (§2.3).
7. 제목 `패널1 — risk score 분포` 저장 후 대시보드에 추가.

---

## 패널 2 — 팩터별 점수 분포 (Lens, small multiples)

7개 팩터 중 무엇이 분포를 끌어올리는지. **팩터 라벨은 한국어.**

`uba-risk-scores`의 팩터 점수 저장 방식에 따라 두 경우로 갈림 — 데이터 뷰 필드 보고 선택:

### 경우 A — 팩터가 doc 1건당 행으로 (`factor` keyword + `score` number)

1. Lens, 데이터 뷰 = `uba-risk-scores`, 차트 = **Bar vertical**.
2. Horizontal axis = `score`, 함수 = Intervals, interval = 10.
3. Vertical axis = Count of records.
4. **Breakdown 아님 → Small multiples**: 필드 = `factor` → 7개 미니 히스토그램 그리드.
5. (참고) 팩터 키는 v12 영문 의미명 — 한국어 라벨 매핑:
   token_violation→토큰규격위반, request_burst→요청수급증, token_replay→토큰재현(Replay),
   response_size_burst→응답크기급증, ip_user_diversity→IP-사용자다양성,
   response_sensitivity→응답민감도, cumulative_exfil→누적유출량.
   ※ 실제 uba-risk-scores 스키마는 아래 "경우 B" (factor_breakdown 객체). 경우 A 미해당.

### 경우 B — 팩터 점수가 doc 1건당 7개 컬럼 (`factor_breakdown.{영문키}`) ★ 실제 스키마

small multiples 불가 (값이 아니라 필드라서). 대신:

1. Lens, 차트 = **Bar vertical**, **7개 metric 레이어**를 한 패널에 추가하거나,
2. 더 간단히 — **패널 2를 7개 작은 패널**로 쪼개 대시보드에 2×4로 배치.
   각 패널: Horizontal axis = `factor_breakdown.ip_user_diversity` 등 Intervals 10, Vertical = Count.
3. 각 패널 제목을 한국어 팩터명으로 (`요청수급증`, `IP-사용자다양성` ...).

> 어느 경우든 X축 0~100, Y축 발동 횟수.
> `factor_breakdown.ip_user_diversity`·`factor_breakdown.response_sensitivity` 패널은 제목에 ★(override 팩터).

---

## 패널 5 — 상위 위험 target 테이블 (Lens datatable, top 20) ★ 멘토 3단계 핵심

수만 명 중 위험 상위 20명만. **`uba-alerts-*` 단독으로 구성** — uba-alerts는
score ≥ 임계치일 때만 기록되므로 이미 "고위험 target 집합"이고, 별도 인덱스 join이 불필요.

1. Lens, 데이터 뷰 = `uba-alerts`, 차트 = **Table**.
2. **Rows**: `target_id`
   - 함수 = Top values, size = **20**, **Rank by = Maximum of `total_score`** (내림차순).
3. **Metrics / 컬럼** (각각 추가):
   | 컬럼 | Lens 함수 |
   |---|---|
   | total_score | Maximum of `total_score` — **Color by value** 켜고 30/70 임계 팔레트 |
   | dominant 팩터 | Last value of `dominant_factor_korean` |
   | attacker_level | Last value of `attacker_level` |
   | (생략) 데이터 유출 | `data_exfiltration_detected` — response_sensitivity descope 로 현재 항상 false → 컬럼 생략 권장 |
   | CVE | Last value of `cve_mapping.id` |
   | 인시던트 요약 | Last value of `llm_report.behavior_analysis_korean` |
   | 마지막 알람 | Maximum of `@timestamp` |
   | target_type | Last value of `target_type` |
4. 정렬: total_score 컬럼 헤더 클릭 → 내림차순.
5. **Drill-down**: 패널 설정 → Create drilldown → "Discover" 또는 패널 7 saved search로,
   `target_id` 필터 전달 → 행 클릭 시 해당 target 전체 로그.
6. 제목 `패널5 — 상위 위험 target Top 20` 저장.

> `dominant_factor_korean` / `behavior_analysis_korean` 는 §3에서 추가하는 필드.
> ES 매핑 적용(`DEPLOY.md`) + Phase 3a 가동 후라야 값이 채워짐. 그 전엔 컬럼이 빈다.

---

## 마무리 — 재export

3개 Lens 패널을 대시보드에 배치 → 대시보드 저장 →
**Stack Management → Saved Objects** → 대시보드 선택 → **Export**
(✅ include related objects) → 받은 파일로 `infra/kibana/uba-dashboard.ndjson` 덮어쓰기.
이러면 NDJSON 한 파일로 8패널 전체가 재현 가능.
