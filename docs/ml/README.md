# ZETTY 공개 데이터 학습 기록

2026-09-26~27 수행. 실행 전에 S/T/A와 예상 문제를 작성하고, 실행 후 R과 실제 문제→원인→개선→재검증을 같은 단계 디렉터리에 기록했다.

| 단계 | 왜 필요한가 | 계획 | 실제 결과 |
|---|---|---|---|
| 01 데이터 audit | 출처·조건·라벨·원본 무결성 확인 | [계획](01-data-audit/README.md) | [결과](01-data-audit/RESULTS.md) |
| 02 전처리 | 서로 다른 관측 단위·결측·충돌 분리 | [계획](02-preprocessing/README.md) | [결과](02-preprocessing/RESULTS.md) |
| 03 특징/분할 | 미래 이력·정답 누출 방지 | [계획](03-feature-and-split/README.md) | [결과](03-feature-and-split/RESULTS.md) · [수식](03-feature-and-split/FEATURES.md) |
| 04 학습 | CPU 비용과 여러 모델 비교 | [계획](04-model-training/README.md) | [실측](04-model-training/RESULTS.md) · [재실행](04-model-training/RUNBOOK.md) |
| 05 평가 | flag rate와 실제 공격 탐지 구분 | [계획](05-evaluation/README.md) | [지표](05-evaluation/RESULTS.md) · [manifest](05-evaluation/manifests/) |
| 06 ZETTY 연결 | 모델과 서비스 계약/조치 책임 분리 | [계획](06-zetty-integration/README.md) | [진행·미완료 조건](06-zetty-integration/RESULTS.md) |

모델은 통계 기준선·Isolation Forest·LOF, 두 클래스가 있는 라벨 train에는 HistGradientBoosting을 비교한다. 데이터별 source/feature/threshold/artifact를 분리한다. 실제 학습 완료 여부와 수치는 각 manifest의 COMPLETED 상태 및 결과 표를 따른다. EClog는 제공자의 Guestbook 조건으로 다운로드·학습을 수행하지 못했다.

원본 [구현 계약](IMPLEMENTATION.md)에 따라 기존 7-factor runtime에 신규 모델을 임시 연결하지 않았다. C-02/producer 및 서비스 feature 의미 검증 후 dry-run→로컬 모의 계정 조치를 구현한다. 현 단계는 공개 자료 offline 학습이다.

[PR #4](https://github.com/ZETTY-ZEROTRUST/uba-analyzer/pull/4)는 원본 develop에서 분기했다. 사용자 기존 checkout과 실험은 보존했다. 원자료/모델/venv는 Git에 포함하지 않는다. 원격 병합 및 실제 보관 위치는 06 결과 문서에서 확인한다.
