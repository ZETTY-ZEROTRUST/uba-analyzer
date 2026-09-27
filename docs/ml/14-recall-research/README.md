# 로그인 이상 탐지율 개선 조사 — STAR

조사일: 2026-09-27. 범위: 공식 문서·원 논문·데이터 제작자 설명과 현재 코드 비교. 이 문서는 다음 실험 제안이며 v3 실행 코드를 변경하거나 학습하지 않는다.

## S — 관측한 문제

v2 학습은 성공했지만 검증 공격6건 중 XGBoost는1건, IF는3건만 탐지했다. test에는 알려진 공격이0건이다. 현재11개 피처는 사용자별 누적 국가/IP/기기/브라우저 빈도와 최초 관측·이력 길이·이전 시도와의 간격이다. 전체 사용자 빈도·ASN·OS·최근 구간 빈도는 없다(`datasets/rba.py`, `study/data.py`).

v3는 깊이·가중치 비교 실험이다. 오탐 기준2%→0.1%와 calibration 꼬리1%→0.1% 변경은 경보 억제이며, 그것만으로 recall이 좋아지지 않는다. 같은 score에 더 높은 threshold를 적용하면 탐지 집합은 줄어든다. sqrt 가중치도 성능 개선 보장이 없고 공격 score를 낮출 수 있다. 기존 높은 가중치가 낮은 성능의 원인이라고 확정하지 않는다.

## T — 목표와 성공 기준

목표는 같은 허용 오탐 수준에서 더 많은 공격을 잡는 것이다. FPR0.01%/0.1%/1%별 recall·precision·FP건수와 정상1만건당 경보를 함께 비교한다. 주 기준0.1%는 사전 고정, 나머지는 trade-off 진단이다. unknown(-1)은 precision/recall/FPR 분모에서 제외하고 별도 경보 건수로 유지한다. 선택 실패를 정상 모델로 포장하지 않는다.

## A — 근거와 적용 순서

### 1. 기존 모델의 누락 공격·동점 점수 진단 (재학습 전)

놓친 공격의 score, threshold와의 차이, 정상 분포 내 순위, score가 같은 정상 행 수, 피처값을 Colab에서 집계한다. 현재 신규 사용자들은 동일11개 피처를 가질 수 있다. 실제 충돌률을 측정하기 전 원인이라고 확정하지 않는다. 같은 입력 벡터의 공격/정상은 깊이를 늘려도 서로 다른 출력으로 분리할 수 없다는 것이 이 진단의 이유다.

99% quantile에서도 관측 calibration 경보율이0.1% 근처로 내려간 모델이 있었다. strict >와 점수 동점의 영향인지 확인해야 한다. >=로 바꾸면 큰 정상 동점 집합이 한꺼번에 경보가 될 수 있으므로 무조건 변경하지 않는다.

### 2. 로그인 이력 길이별 threshold (기존 배열 활용 가능)

신규/짧은 이력/충분한 이력 cohort별 정상 calibration 점수 분포를 사용한다. 예시 구간0,1–4,5–19,20+는 새 실험의 가설이며 논문 최적값이 아니다. 구간·최소표본·fallback은 validation 보기 전에 고정한다. 데이터가 부족한 cohort는 전체 threshold 사용. 미래/현재 로그인은 이력 통계에 넣지 않는다.

원 연구는 이력 크기에 따라 위험 점수와 사용자 경험이 달라지고, 이력 크기에 따른 동적 threshold를 제안한다. 이를 우리 XGBoost에 옮기는 것은 검증이 필요한 응용이다. [Wiefling et al., §§7,10](https://riskbasedauthentication.org/download/rba-largescale-onlineservice-paper.pdf)

### 3. 글로벌 대비 개인 빈도 및 ASN/OS 피처 (원본에서 새 전처리 필요)

국가→ASN→IP 및 OS/브라우저 계층에 대해 개인·전체 빈도와 smoothing된 빈도 대비를 추가한다. 새 ASN/새 OS, 알려진 ASN의 새 IP 같은 차이를 구분한다. raw ID를 숫자 크기로 학습하거나 합성 IP를 실제 GeoIP로 해석하지 않는다. 기존11열 x.bin만으로 ASN/OS/전역 범주는 복원할 수 없다.

Freeman 방식은 전체와 개인의 확률 및 희소 범주 smoothing을 사용한다. 축약한 빈도 대비를 XGBoost 입력으로 쓰는 실험과 독립 Freeman 계열 기준선을 분리한다. 원 식을 임의 합산점수로 대체한 뒤 논문 재현이라고 부르지 않는다. [Freeman et al., §§III–IV](https://doi.org/10.14722/ndss.2016.23240)

데이터 제작자는 범주형 전역/개인 통계를 보존했다고 설명하며 IP·국가·ASN·UA·OS·브라우저·기기를 연구 재현에 사용한다. 반면 시각은 무작위성이 있고 RTT는 합성 위치와 로그인 성공 여부에 따라 생성됐다. 시간대·impossible travel·RTT를 무조건 넣어 얻는 성능은 합성 절차의 흔적일 수 있어 후순위 ablation으로 둔다. [데이터 제작자 설명](https://zenodo.org/records/6782156)

### 4. 고정 시간 구간의 반복 평가

과거 train→별도 calibration→그 이후 평가를 여러 사전 고정 기간에서 반복하고 시간 embargo를 유지한다. 공격이 없는 기간을 버리거나 좋은 결과가 나올 때까지 경계를 이동하지 않는다. 각 기간의 공격0건은 recall 미정의로 표시한다. 겹치는 평가 행/공격을 독립 사례처럼 중복 합산하지 않는다. 이미 확인한 데이터는 탐색용이며 새 독립 확인 자료/시나리오가 필요하다. [scikit-learn 시간 교차검증](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.TimeSeriesSplit.html)

임계값은 학습과 별도 자료에서 조정해야 한다. 기본 stratified CV를 시계열 데이터에 그대로 적용하지 않는다. [scikit-learn threshold 문서](https://scikit-learn.org/stable/modules/classification_threshold.html)

### 5. 깊이보다 통제된 비교

v3 결과를 먼저 보존한다. 다음 비교는 한 번에 한 축만 바꾼다: 기존 피처/threshold → cohort threshold → 풍부한 피처 → 두 개선 결합. 각 단계에서 v2 깊이6 기준선과 v3 우수 후보를 동일 분할·FPR 예산으로 비교한다. 깊이가 늘면 더 많은 학습 정보가 필요하고 과적합 가능성이 커진다. 공격107건을 복제해도 독립 공격 정보가 늘지는 않는다. [XGBoost3.0.5 공식 tuning](https://xgboost.readthedocs.io/en/release_3.0.0/tutorials/param_tuning.html)

ROC-AUC만으로 성공을 판단하지 않는다. AP/PR곡선과 실제 경보 precision을 함께 보고한다. AP는 유병률/공격 비율에 의존하므로 분포가 다른 split의 숫자를 직접 성능 향상으로 간주하지 않는다. [Saito & Rehmsmeier, 2015](https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0118432)

## R — 현재 결론

웹 조사와 코드 대조 완료. 우선순위는 **누락/동점 진단 → cohort threshold → 글로벌/개인·ASN/OS 피처 + Freeman 기준선 → 시간 반복 평가**다. v3 깊이 비교는 유효한 탐색 실험이지만 새 피처·threshold 접근을 대신하지 못한다. 실제 성능 향상 수치나 논문의99% 공격 차단 성과를 현재 실험에 전용하지 않는다. 모델 코드·현재 Colab 실행은 이 조사에서 변경하지 않았다.
