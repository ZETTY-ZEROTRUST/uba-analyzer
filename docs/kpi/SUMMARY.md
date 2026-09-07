# KPI SUMMARY — Phase D 산출물

> **발표/자소서 핵심 1 장.** PROGRESS_TODO Phase 6-4 의 최종 산출.
> 측정 기준 시각: 2026-05-25 (T0 = 2026-05-24 17:55:37 KST 공격 발사 → D-2 = 2026-05-25 02:18 KST 재채점).

---

## 🎯 핵심 3 KPI

| KPI | 값 | 측정 정의 |
|---|---|---|
| **TPR** (시나리오 단위) | **6/6 = 100%** | 공격 시나리오 중 *v2 알람* (`total_score ≥ 50`) 1 회 이상 발동된 비율 |
| **FPR** (전체 정상 트래픽) | v1 1.516% → **v2 0.080%** (-94.7%) | 정상 윈도우 중 알람 발동 비율. v1 = soft cap 미도입 가정, v2 = 실제 |
| **MTTD** | 약 **5~10분** (시나리오별) | 공격 윈도우 종료 → batch 채점 ts 차이 (batch 주기 5분 + 윈도우 5분) |

→ 한 줄 요약: **"6/6 100% 탐지 + 정상 FP 94.7% 감소 + 5~10분 평균 탐지 지연"**.

---

## 🛡️ 시나리오 매트릭스 (TPR detail)

| 시나리오 | 공격 특성 | max v2 score | 알람 윈도우 수 | 핵심 발동 팩터 | 의미 |
|---|---|---|---|---|---|
| **S2** token hijack | victim 정상(KR cgnat_kr) → hijack(US cloud) 동일 jti | **55** | 1 | `token_replay` base 35 + class crossing | 키 외 토큰 통째 탈취 detection |
| **S4** forged-sub sweep | 단일 IP(AWS) × 100 sub 순차 | **100** | 12 | `ip_user_diversity` override | 쿠팡 유출 패턴 직접 재현 |
| **S5** 분산 enum | 51 IP × 100 sub 순차 | **100** | 35 ★ | **Route B** `ip_user_diversity` ASN-윈도우 | 단일 IP 회피 우회 무효화 |
| **S5b** 분산 random | 51 IP × random sub | **100** | 27 | Route B | sub 순서 noise 도 무효화 |
| **S6** Slow & Low | 매 ~47초 1 회, 6 h | **100** | 20 | `ip_user_diversity` 24h + `cumulative_exfil` | 쿠팡 7개월 미탐지 재현·대응 |
| **S8** 장수 토큰 | TTL 7200s 위조 토큰 8건 | **80** | 8 | `token_violation` T007 (exp-iat>3600) | 토큰 규격 위반 즉시 검출 |

**TPR 100%** 의 의미: **v1=v2 동일** — soft cap 이 *진짜 공격 detection 엔 영향 0*. cap 의 *isolated effect = 정상 FP 만 제거*. 디자인 정밀도 검증.

---

## ⚖️ FPR v1 vs v2 (Phase B-2 soft cap 의 정량 효과)

### 코호트별

| 코호트 | 총 윈도우 | v1 알람 | v2 알람 | v1 FPR | v2 FPR | Δ |
|---|---:|---:|---:|---:|---:|---:|
| **cgnat_kr** (정상 KR NAT) | 62,369 | 1,019 | **0** | 1.634% | **0.000%** | **+1.634p** ★ |
| **AMBIG_NAT** (cloud, 50 sub) | 485 | 37 | 37 | 7.629% | 7.629% | +0.000p (대조군) |
| cloud-other (잔재) | 490 | 14 | 14 | 2.857% | 2.857% | +0.000p |
| other (정상) | 7,632 | 6 | 6 | 0.079% | 0.079% | +0.000p |
| **전체 정상 (합계)** | **70,976** | **1,076** | **57** | **1.516%** | **0.080%** | **+1.436p (94.7% 감소)** ★ |

### 해석

- **cap 의 isolated effect** = cgnat_kr 의 1,019 알람 → 0. 정확히 *whitelist 된 코호트만* 영향. 다른 코호트는 v1=v2 동일.
- **AMBIG_NAT 7.629% 유지** = 디자인 정직성 evidence. cap 을 *모든 NAT* 로 일반화 안 함 → cloud NAT 는 *상시 의심* 유지. *현실적 비-0% FPR*.
- **94.7% FP 감소** = SOC 운영의 *알람 fatigue* 직접 해소. 자기-개선 서사 #2 의 정량 ground.

### controlled experiment 셋업 (Phase B 결정)

| | cgnat_kr (S7-cafe) | cloud (AMBIG_NAT) | 유일한 변수 |
|---|---|---|---|
| 풀 크기 | 50 sub | 50 sub | (동일) |
| 트래픽 분량 | 비슷 | 1,500 docs | (동일) |
| **ip_class** | cgnat_kr | cloud | **★ soft cap 화이트리스트 여부** |

→ S7-cafe vs AMBIG_NAT 의 *유일한 변수* 가 `ip_class` ↔ cap 발동 여부. 다른 모든 조건 동일. **textbook controlled experiment**.

---

## ⚠️ Descope 항목 (의도된 미측정)

| 항목 | 사유 | 대안 / 향후 |
|---|---|---|
| **데이터 유출 탐지율** | `response_sensitivity` 팩터의 backend AOP 미연동 (Option B descope, 2026-05-19 결정) | PII counter 별도 future work. 발표 슬라이드 #8 "Future work" 로 표기 |
| **per-doc precision** | doc 단위 precision = (attack alarm doc) / (all alarm doc) 는 *정상 NAT noise* 가 dominant 라 의미 작음 | *target_id 단위* operational precision 으로 대체 가능 |
| **F-cross** (jti 발급 ↔ 사용 매칭) | auth-server 발급 로깅 자체 미구현 (2026-05-19 stretch 확정) | future work 슬라이드. **Route B 가 S5/S5b 를 *대신* 커버** |

---

## 🧪 자기-개선 6 서사 — 측정 vs 정성

| # | 서사 | 측정 가능? | 결과 |
|---|---|---|---|
| 1 | degenerate baseline → 입체 baseline (분산 주입) | ⭐ 측정 (Phase B) | std≈0 → std>0 (이번 baseline 의 7 metric p99 분포로 검증) |
| 2 | NAT 과탐 → soft cap | ⭐ 측정 (Phase D) | **FPR 1.516% → 0.080% (-94.7%)** ★ |
| 3 | 분산 회피 → ASN 집계 (Route B) | 정성 + 측정 (S5 score=100, 35 win) | S5 = "단일 IP 회피 공격이 ASN 단위에서 들통남" 의 *측정 demo* |
| 4 | LLM 환각 → grounding 검증 | 정성 | MITRE/CVE ID validator (코드) |
| 5 | 10k fetch 잘림 → scan 페이지네이션 | 측정 | 8.5% → 100% (PROGRESS_DONE 2026-05-20) |
| 6 | 이진 token_replay → graded 모델 | 정성 + 측정 (S2 score=55) | v13 base+modifier — S2 가 *정확히 graded* 동작 |

→ **#1·#2·#5 가 *수치* 개선**. #2 가 *Phase D 의 측정 결과* — 발표 임팩트 1순위.

---

## 📊 LLM 인시던트 리포트 (Phase 3a / 3b, 추가 산출)

`uba-alerts-*` 인덱스의 `llm_report.behavior_analysis` (한국어, Haiku 4.5 + ReAct + 3 tool) — Discover row expand 로 표시 (Option B 매핑 = enabled:false, 검색 안 되고 표시만).

(Phase 3a 트리거 결과는 별도 캡처 — `docs/kpi/figures/llm_alert_sample.png` 등 발표 자료에 포함 예정.)

---

## 📐 측정 환경 / 재현 명령

```bash
# baseline 부트스트랩 (D-0)
.venv/bin/python pipeline.py --hours 168

# 공격 발사 (D-1, T0)
cd attack-simulation && ./run_all.sh   # S2/S4/S5/S5b/S6/S8 동시

# 운영 배치 (D-2 — baseline 재사용)
.venv/bin/python pipeline.py --hours 168 --no-baseline

# 분석 (D-3)
ES_HOST=https://localhost:9200 ES_USER=elastic ES_PASS=$ES_PASS \
  python uba-analyzer/scripts/compute_v1_v2_fpr.py
# → docs/kpi/fpr.md / v1_v2_raw.json / figures/v1_v2_fpr.png 생성
```

**박스 / 인프라**:
- UBA: i-0e06820c477644613 (`/opt/zeti-uba/.venv/bin/python3`)
- ELK: i-09634c7f2a6fe739b (ES 8.19.3 / Kibana 8.19, https://10.0.41.10:9200)
- ALB: ZETI-alb-133662152.ap-northeast-2.elb.amazonaws.com

---

## 🔗 관련 산출물

- `docs/kpi/fpr.md` — 자동 생성 표
- `docs/kpi/v1_v2_raw.json` — 매트릭스 raw + GT scenarios
- `docs/kpi/figures/v1_v2_fpr.png` — v1 vs v2 코호트별 bar chart
- `docs/kpi/figures/uba_d0_score_dist.png` — D-0 multimodal discrete
- `docs/kpi/figures/uba_d0_cohort_cap.png` — soft cap quantified
- `docs/kibana/PHASE_5_TROUBLESHOOTING.md` — Kibana 대시보드 정합성 fix 기록
- `infra/kibana/uba-dashboard.ndjson` (patched) — SOC 대시보드 5 패널
- `scripts/compute_v1_v2_fpr.py` — Method B 분석 스크립트
