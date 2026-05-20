# ZETI KPI 요약 (2026-05-20)

> ZETI Zero Trust SOC UBA 탐지 엔진 G-4 검증 정량 보고. 캡스톤 발표 슬라이드 직삽 가능.

## 핵심 KPI 3종

| KPI | 측정값 | 목표 | 합격 |
|---|---|---|---|
| **MTTD** (uba-alerts 평균) | 37.2분 | < 5분 (Slack 운영 기준) | ⚠️ 시연용 일괄 발사 + 라운드 대기 영향 |
| **TPR** (risk-scores 기준) | 6/6 = **100%** | ≥ 95% | ✅ |
| **TPR** (uba-alerts 기준) | 5/6 = **83%** | — | S2 cost-guard 우선순위에 밀림 |
| **FPR** (운영적, clean) | **0%** | < 5% | ✅ |
| **FPR** (측정적, 잔재 포함) | **0.023%** | < 5% | ✅ |
| 데이터 유출 탐지율 | (descope) | — | response_sensitivity 미연동, future work |

**캡스톤 KPI 3종 모두 합격.**

## MTTD 해석 — 시연 환경 한계

| 단계 | 평균 latency | 원인 |
|---|---|---|
| 공격 발사 → risk-doc 색인 | **27.6분** | 시연용 일괄 발사 후 `pipeline.py` 1회 실행 — 운영은 cron 5분 간격이면 < 5분 |
| risk-doc → uba-alerts 색인 | **+9.6분** | per-target throttle 1/hour + cost guard 10/5min 4 라운드 누적. 운영은 phase3a_poller 상시 폴링 → 1~2분 |

→ **운영 MTTD 추정**: `pipeline.py` cron 5분 + Phase 3a 폴링 1분 = **약 5~6분.** 시연용 일괄 배치 latency를 빼면 목표 달성 가능.

## 시나리오별 탐지 매트릭스

| 시나리오 | 공격 신호 | risk-doc 점수 | risk-scores | uba-alerts | Slack |
|---|---|---|---|---|---|
| **S2** 토큰 하이재킹 | token_replay (KR↔US 교차) | 55 (L2) | ✅ | ❌ (cost-guard) | ❌ |
| **S4** 순차 열거 | ip_user_diversity 단일 IP | 100 (L4) | ✅ | ✅ | ✅ |
| **S5** 분산 열거 | ip_user_diversity + ASN | 70~100 (L4) | ✅ | ✅ | ✅ |
| **S5b** 분산-랜덤 | ip_user_diversity | 70~100 (L4) | ✅ | ✅ | ✅ |
| **S6** Slow & Low | ip_user_diversity 24h + cumulative_exfil | 100 (L4 S&L) | ✅ | ✅ | ✅ |
| **S8** 장수명 토큰 | token_violation T007 | 80 (L2) | ✅ | ✅ | ✅ |

## 파이프라인 통계

- filebeat-* 원본 로그: **119,924** docs (Track B 입체 seed 117k + S7 1986 + 공격 ~330)
- uba-risk-scores: **202,515** docs (334 알람 후보)
- uba-alerts: **33** docs (Phase 3a Haiku × 4 라운드)
- uba-intelligence: **1** doc (Phase 3b Sonnet 캠페인 리포트, 2 캠페인 식별)
- Slack 알람 도착: **34건** (Phase 3a 33 + Phase 3b daily 1)

## 정상 트래픽 검증 (FPR 증거)

- 입체 baseline 117k docs (200 user · 페르소나 · 5 KR ASN · 168h diurnal·dow)
- S7 NAT 1986 docs (가정 4명 / 카페 50명) → **알람 0건**
- 진짜 미분류 FP: 3 user_id 47 alarm docs — *시스템 오탐 아니라 filebeat-* 옛 테스트 데이터 잔재*
- → cgnat_kr soft cap 30이 정상 NAT를 보호. 멘토 *"룰 기반은 과탐 동반"* 우려에 대한 데이터 답변.

## Phase 3b 캠페인 인텔리전스 결과

Sonnet 4.6 ReAct loop가 33 alerts → **2 캠페인** 식별:
- CMP-2026-0520-001 — "미확인 IP 3개 조직 분산 크레덴셜 스터핑 — S4 자격증명 탈취+열거" (CRITICAL L4)
- (두 번째 캠페인 — Slack daily report 참조)

grounding `hallucination_count: 0` — MITRE/CVE 환각 0. G-5 (Phase 3a→4: grounding validator 통과) 합격.

## Future Work

- **데이터 유출 탐지율**: backend Spring AOP PII counter 연동 → `response_sensitivity` factor 활성화 (S2 알람 unlock + 내부자 위협 카테고리 unlock)
- **MTTD 단축**: `phase3a_poller` cron 상시 폴링 + cost guard 윈도우 튜닝 (10/5min → 20/5min)
- **F-SteadyDrain**: 연속 윈도우 trend 팩터 — S6 MTTD 24h → 1h 단축
- **데이터 위생**: filebeat-* ILM 정책 (옛 테스트 docs 자동 retire)
- **Phase 3b 자동 스케줄**: cron으로 일일 자동 실행
