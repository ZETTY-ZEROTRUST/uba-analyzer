# 전체 자료·다중 버전 비교 — 실행 전 STAR 계획

작성: 2026-09-27. 사용자 승인: 하루 이상 걸려도 전체 자료와 여러 버전/모델의 학습·성능 비교를 수행한다. 이 문서는 실행 전 계획이며 실제 결과는 별도 RESULTS/manifest에 기록한다.

## S — 상황

1차는 RBA 첫25만 행, RBD phishing desktop 한 파일, 모델 train 최대1만 개로 제한했다. 짧은 prefix의 ATO 정답은 네 개뿐이었다. 전체 기간·다른 위험 task·모델 차이를 판단할 수 없다.

## T — 목표와 이유

Online Shop 전체 원본, RBA ZIP 내 CSV 전체, RBD24의 12개 task/device 파일을 각각 독립 처리한다. EClog는 제공자의 필수 응답 조건을 확인하고 충족 가능한 정당한 경로로 확보한다. 전체 입력을 처리하되 시간순 holdout과 unknown/품질 제외를 유지한다. 모든 행을 train에 넣어 평가 정답을 누출하지 않는다.

## A — 실행 설계

- RBA 전체 기간을 streaming 처리하고 특징·timestamp·entity·label은 disk-backed 배열로 저장한다. 사용자별 과거 이력은 SQLite와 bounded LRU cache로 관리한다. 같은 시각의 모든 관측은 이전 시각 이력만 사용한다. 시작부터 끝까지 검사한 행 수·제외 수·원본 CRC/checksum을 기록한다.
- RBD 파일별 label/task/관측을 분리한다. 기존 허용 특징만 선택해 정답 유래 지표를 제외하고 같은 entity/time 충돌을 격리한다. 같은 user/window가 다른 파일에 존재하는 것은 별도 task 간 중복으로 audit하며 파일 간 train/test를 혼합하지 않는다.
- 시간순 train50% → threshold calibration15% → 모델 선택 validation15% → 최종 test20%. source별 embargo를 유지한다. HTTP와 phishing desktop의 기존 test는 이미 확인한 자료이므로 새로운 blind holdout이라고 부르지 않는다. 전체 RBA의 후반부와 추가 RBD 파일은 신규 최종 평가다.
- 같은 source의 모든 후보는 같은 분할·특징·입력으로 비교한다. baseline, Isolation Forest 두 설정×두 seed, LOF 두 이웃 수(계산 가능한 자료), HistGradientBoosting 두 설정, RandomForest, streaming SGDOneClassSVM·MiniBatchKMeans를 비교한다. 설정을 최종 test 전에 고정한다.
- full RBA의 수천만 train 행에 정확한 LOF를 실행하면 이웃 계산의 쌍별 비용이 지나치게 커진다. 전체 데이터 학습 후보로 선형/mini-batch 모델을 사용하고 LOF의 전체 미실행을 명시한다. 작은 LOF 표본을 전체 학습이라고 부르지 않는다. IF의 알고리즘 내부 tree subsample과 데이터 prefix 제한도 구분한다.
- train-only scaler/통계, calibration threshold(1% tail), validation에서 recall 우선·FPR≤2% 조건으로 후보를 선택한다. 유효 양성/음성이 없는 source는 탐지 성능 우승자를 정하지 않는다. 최종 test의 precision/recall/FPR/AP/ROC-AUC·분모와 95% 비율 구간·seen/unseen cohort·시간/RSS/모델 크기를 보고한다. 최종 test로 재튜닝하지 않는다.
- 모델 version/parameters/seed, source/feature/split/code/environment hash, 전체 처리·실제 fit 행 수를 저장한다. 중단/실패는 RUNNING/FAILED 상태로 남기고 완료 artifact만 재사용한다. 데이터/모델은 Git 밖에 보관한다.

## 예상 문제 → 개선 계획

- RAM 과다 사용 → bounded 스트리밍·mmap·SQLite 이력; 큰 중간 배열을 한 번에 복제하지 않는다.
- 긴 다운로드 연결 중단 → 32MiB 구간 검증·최종 공식 checksum, 제한된 병렬 다운로드.
- 희소 ATO·분포 변화 → full-period 평가·분모/구간·source별 결과, 낮은 성능을 숨기지 않는다.
- 모델별 장시간 실행 → 진행 manifest·로그·단계별 완료 checkpoint, 계산 불가능한 후보는 이유와 대체 모델을 명시한다.
- 제공자 Guestbook/원본 merge 권한 → 허위 개인 정보나 권한 우회 없이 막힌 항목을 별도 기록한다. 독립 작업은 계속한다.

## R — 실행 전

아직 전체 학습을 완료하지 않았다. 아래 단계별 결과에 실제 명령·행 수·비용·성능·오류 및 개선을 추가한다. 기존 1차 결과는 별도 보존한다.
