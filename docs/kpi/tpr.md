# TPR — True Positive Rate

> 발사한 6 시나리오가 탐지 파이프라인 각 단계에서 잡혔는지.

| 시나리오 | risk-scores (탐지) | uba-alerts (LLM) | Slack (전송) | 비고 |
|---|---|---|---|---|
| S2 | ✅ | ❌ | ❌ | score 55 < cost-guard 우선순위(70+ 다수)에 밀림 |
| S4 | ✅ | ✅ | ✅ |  |
| S5 | ✅ | ✅ | ✅ |  |
| S5b | ✅ | ✅ | ✅ |  |
| S6 | ✅ | ✅ | ✅ |  |
| S8 | ✅ | ✅ | ✅ |  |

## TPR

- **TPR (risk-scores 기준)** = 6/6 = **100%**
- **TPR (uba-alerts 기준)** = 5/6 = **83%**
- **TPR (Slack 기준)** = 5/6 = **83%** (uba-alerts 색인 == Slack 전송)

## 해석

- **detection layer**(risk-scores)에서 100% 잡힘 — 7팩터 + Track B 입체 baseline + Route B + token_replay graded 모델 조합으로 6 시나리오 전부 점수화.
- **alerting layer**(uba-alerts/Slack)에서 5/6 — S2 token_replay 55점이 cost-guard 처리 우선순위에 밀림. 이건 LLM 비용 가드의 *의도된* 동작이고, S2의 risk-doc은 이미 색인됨(분석가는 risk-doc 단계에서 확인 가능).
