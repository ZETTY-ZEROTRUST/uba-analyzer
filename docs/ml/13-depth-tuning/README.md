# 깊이·불균형·경보 기준 개선 — STAR

## S
v2 완료 아티팩트에서 XGBoost 4개는 검증 공격6건 중1건, IF는3건을 탐지했다. IF seed42 오탐은25,220건이다. train 공격107/정상14,146,289로 balanced 가중치 비율이 약132,208배다. 검증6건·test0건으로 탐지 성능 확정이 불가능하다.

## T
기존 배열·시간 분할을 보존하면서 깊이 확대 효과와 공격 가중치 완화 효과를 비교한다. 허용 FPR2%를 그대로 적용해 IF가 선택되는 문제를 개선한다. 기존 v2 결과를 덮거나 test를 보고 threshold를 선택하지 않는다.

## A (구현 전)
- 새 colab-gpu-v3 프로파일: v2 depth6/400 기준선 + depth8/10/12 ×400/800 balanced 후보 + depth8/10/12 800회 sqrt-ratio 가중치 후보 = XGBoost10개. 기존 IF2개 포함 총12개.
- 새 깊은 후보는 eta .05, lambda10, min_child_weight10, max_delta_step1로 규제. depth 효과만 비교할 수 있도록 depth8/10/12의400회 후보는 기존 eta/lambda/규제를 유지한다. 800회 후보는 추가 규제 효과가 섞인 별도 후보로 표시.
- balanced와 sqrt ratio 모두 전체 학습행을 사용하며 평균 weight1로 정규화. 클래스 비율은 train 라벨에서만 계산. quantile CPU → CUDA fit 우회 유지.
- 정상 calibration의99.9% 분위수(strict >)를 주 임계값으로 고정. validation FPR<=0.1%, recall>0인 모델만 선택. 정상1만건당 오탐10건 기준이며 실제 calibration/validation/test FPR은 각각 보고한다.
- 99%,99.9%,99.99% 분위수의 validation operating points도 저장하되 이를 보고 주 임계값을 바꾸지 않는다.
- 이미 v2 test를 확인했으므로 v3는 exploratory, independent validation 필요로 표시. test 공격0이면 탐지 성능 미검증임을 manifest에 명시. 시간 분할을 라벨에 맞춰 임의 이동하지 않는다.
- 현재 단일 셀 Colab 노트북에 v3를 기본으로 연결. 이전 v1/v2와 resume snapshot은 보존. 로컬 학습 없음.

## R
로컬 mock 회귀 검사와 Colab 실행 준비까지 수행한다. 실제 성능 향상은 v3 ZIP 결과를 확인해야 한다. 피처 개선·공격 포함 별도 시간 구간 검증은 이 깊이 비교 결과와 함께 후속 설계가 필요하다.

근거: https://xgboost.readthedocs.io/en/stable/parameter.html?highlight=gblinear (max_depth, min_child_weight, max_delta_step). 깊이가 늘면 메모리 및 과적합 위험도 커지므로 무제한 깊이를 사용하지 않는다.

## 검증 결과

2026-09-27: depth/weight/selection 단위검사 + GPU mock 전체 v2/v3 연구 + checkpoint/복구 검사 총26개 통과. v3 12후보 전체 fit/calibration/validation/selection/test 흐름은 fake estimator로 검증했다. GPU fit은 로컬에서 실행하지 않았다. 스크립트/노트북 구문 및 diff 검사 통과. 실제 Colab v3 학습, VRAM·시간·성능 향상은 아직 미확인이다.

실행: `notebooks/zetty_rba_colab.ipynb`의 독립 코드 셀 전체를 현재 Colab 새 셀에 복붙한다. 기존 prepared 경로가 남아 있어야 하며 v2 결과는 그대로 보존된다. GPU 학습 v3 12개를 새 디렉터리에 저장하고 완료 ZIP을 다운로드한다. Drive 백업은 계속 비활성이다. v2를 다시 실행하려면 recover_colab.py에 `--profile colab-gpu-v2`를 지정한다.
