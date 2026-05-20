# FPR — False Positive Rate

> 정상 트래픽(seed baseline + S7 NAT)이 잘못 알람을 받은 비율.

## 알람 후보 분류 (score ≥ 50)

| 분류 | doc 수 | 비고 |
|---|---|---|
| 전체 risk-score 윈도우 docs | 202,515 | filebeat-* 119,924 × 평균 1.7 window |
| 알람 후보 (score ≥ 50) 총합 | 334 | |
| └ 현재 6 시나리오 공격 매칭 (true positive) | **287** | S2/S4/S5/S5b/S6/S8 + 공격 ASN 집계 |
| └ **이전 테스트 잔재 (filebeat-* 미정리)** | **47** | user_id `140002100/03/06` — Track B 재seed 전 공격 docs |
| └ 진짜 false positive (현 데이터 기준) | **0** | |

## 분류 상세

### TP — 공격 매칭 (287건)

| 패턴 | doc 수 | 시나리오 |
|---|---|---|
| RFC5737 (192.0.2.* / 198.51.100.* / 203.0.113.*) | 98 | S5/S5b 분산 IP |
| 45.32.* (Vultr / AS20473) | — | S5 분산 IP (이미 attack 리스트 포함) |
| 15.164.10.40 (AWS Seoul) | — | S4 (attack 리스트 포함) |
| 124.216.198.105 (KR 울산 방송망, AS45361) | 9 | **S8 실제 source IP** (console 출력엔 `ip=-`로 잘못 표시) |
| user:140000002~009 / 140000518 | 27 | S8 / S2 (attack 리스트 포함) |
| ASN 집계 (AS16509 / AS20473 / AS36646) | 27 | Route B 공격 ASN |

### 진짜 FP — 잔재 데이터 (47건)

| target_id | alarm doc 수 | score 범위 | 추정 출처 |
|---|---|---|---|
| `140002100` (user) | 24 | 54~63 | 이전 테스트 (현 6 시나리오와 매칭 안 됨) |
| `140002103` (user) | 13 | 54~63 | 이전 테스트 |
| `140002106` (user) | 10 | 54~63 | 이전 테스트 |

→ `140002100`대 user_id는 현 seed(140000000~199)도, S7(140000700~849)도, 어떤 공격 시나리오의 victim pool도 아님. **filebeat-* 인덱스에 옛 테스트 docs가 남아 그 토큰 신호가 채점된 것** — *시스템이 정상 트래픽에 오탐한 게 아니라 데이터 위생 문제.*

## FPR 두 가지 관점

| 지표 | 값 | 해석 |
|---|---|---|
| **운영적 FPR** (clean data — Track B seed 117k + S7 1986만) | **0%** | G-3 + S7 검증대로. cgnat_kr soft cap 30 / 정상 user는 token rule 무위반 |
| **측정적 FPR** (filebeat-* 잔재 포함) | **0.023%** (= 47 / 202,515) | 옛 테스트 docs까지 포함한 보수적 측정 |

**두 수치 모두 목표 FPR < 5% 안에서 합격.**

## 정상 트래픽 구성

- **Track B 입체 seed**: 117,604 docs / 200 user × 페르소나 3종 / 5 KR 캐리어 ASN / 168h × diurnal·dow 패턴
- **S7 NAT 검증**: 1,986 docs
  - 가정 NAT (`121.135.40.77`, 4명 공유): 485 docs
  - 카페 NAT (`175.197.50.12`, 50명 공유): 1,501 docs

## S7 알람 결과 — 핵심 증거

- `175.197.50.12` (카페): risk-doc 356건, **전부 score 30** (`cgnat_kr` soft cap, `is_nat_whitelisted=True`)
- 임계 50 미달 → **알람 0건**

이게 멘토 지적 *"룰 기반은 과탐 동반"* 에 대한 데이터 답변. ZETI는 z-score baseline 정규화 + ip_class soft cap으로 NAT를 보호 → 과탐 0.

## 운영 측정 한계 / Future Work

- 본 측정은 *합성 정상 트래픽*(Track B + S7) 기준. 실 운영 트래픽의 다양성이 더 클 수 있어 운영 단계에서 재측정 필요.
- 발표 후 cleanup: `DELETE filebeat-*` 후 fresh re-seed + 공격 재발사로 진짜 0% FPR 보고 가능.
- **데이터 위생 권장**: 운영 시 filebeat-* ILM 정책으로 옛 docs 자동 retire (현재 미설정).
