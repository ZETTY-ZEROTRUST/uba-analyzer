# 특징과 분할 STAR 결과

## S/T — 보장하려는 경계

자료가 서로 다른 사용자·시각·라벨 의미를 가진다. 시간순 분할과 train-only 전처리, 로그인 과거 이력만의 특징을 보장하는 것이 과제다.

## A — 구현 및 발견한 문제 개선

`datasets/*`에서 source별 특징을 만들고 `training/split.py`에서 unique timestamp 기준 분할한다. 수식·순서·단위·결측 정책은 [FEATURES](FEATURES.md)에 기록했다.

검토 중 label이 모두 -1인 라벨 task를 단순 unlabeled source로 오인할 수 있는 경계를 발견했다. `Observations.label_kind`로 자료의 라벨 의미를 명시해 RBA/RBD의 unknown-only 표본이 정상 reference로 학습되지 않도록 수정했다. HTTP의 라벨 부재 실험만 별도 허용한다.

## R — 실제 검증

- 시간 묶음이 split에 겹치지 않고 embargo가 적용되는 fixture 통과.
- 같은 시각의 로그인은 동일한 이전 이력만 사용. 현재 성공/공격 라벨 변경이 특징에 영향을 주지 않으며 이후 행의 맥락을 바꾸어도 이전 특징이 유지되는 fixture 통과.
- 과거로 돌아가는 RBA 시각 거부, prefix 마지막 시각 묶음 제외, 필수 맥락 누락 제외 통과.
- 전부 unknown인 라벨 task는 output 생성 전에 `insufficient_reference_rows`로 거부되는 fixture 통과.
- HTTP의 최종 분할은 6,729 / 4,243 / 4,327행, RBD는 10,266 / 2,552 / 2,144행이다. 제거된 embargo 표본과 정확한 시각 범위는 [평가 manifest](../05-evaluation/manifests/)에 남겼다.

HTTP session ID 부재, RBD 원 window 길이 미확정, RBA prefix 이력 한계는 해결됐다고 주장하지 않는다. 신규 사용자 지표는 시간 test 내 unseen 부분집합이며 독립 사용자 holdout을 별도로 수행한 것은 아니다.

RBA 실제 분할: train149,993 / calibration45,648 / test48,541, embargo5,804행 제외. 비지도 fit는 train reference에서 seed42로 고른 10,000행이다. 원 timestamp가 가진 소수 초 경계를 manifest에 그대로 보존한다.
