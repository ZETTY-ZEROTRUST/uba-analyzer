# 독립 평가 STAR 결과

## S/T — 해석 원칙

공개 데이터의 수치적 이상이 실제 공격 탐지를 입증하는지 확인한다. 정답 없는 flag rate와 정답 기반 FPR을 구분한다. 모델 점수는 공격 확률이 아니며 test 결과로 임계값을 조정하지 않았다.

## A — 평가 방법

시간순 holdout과 자료별 embargo를 적용했다. calibration reference의 99% quantile(method=higher), strict `>`를 사용한다. seen/unseen 사용자 부분집합은 manifest에 별도 기록한다. 신규 사용자 전용 독립 학습 분할이나 incident recall·탐지 지연은 검증하지 않았다.

## R — 실제 지표

| 자료 | 모델 | test N | TP/FP/FN/TN | flag rate | precision | recall | FPR |
|---|---|---:|---|---:|---:|---:|---:|
| online-shop-final | robust_distance | 4,327 | unknown labels | 0.000% | — | — | — |
| online-shop-final | isolation_forest | 4,327 | unknown labels | 0.924% | — | — | — |
| online-shop-final | lof | 4,327 | unknown labels | 1.202% | — | — | — |
| rbd24-final | robust_distance | 2,144 | 4/92/413/1635 | 4.478% | 4.167% | 0.959% | 5.327% |
| rbd24-final | isolation_forest | 2,144 | 0/45/417/1682 | 2.099% | 0.000% | 0.000% | 2.606% |
| rbd24-final | lof | 2,144 | 11/46/406/1681 | 2.659% | 19.298% | 2.638% | 2.664% |
| rbd24-final | hist_gradient_boosting | 2,144 | 65/13/352/1714 | 3.638% | 83.333% | 15.588% | 0.753% |
| rba-final | robust_distance | 48,541 | 0/0/1/43927 | 0.000% | — | 0.000% | 0.000% |
| rba-final | isolation_forest | 48,541 | 1/452/0/43475 | 0.954% | 0.221% | 100.000% | 1.029% |
| rba-final | lof | 48,541 | 0/480/1/43447 | 1.053% | 0.000% | 0.000% | 1.093% |
| rba-final | hist_gradient_boosting | 48,541 | 0/0/1/43927 | 0.000% | — | 0.000% | 0.000% |

## 문제·원인·판단

- HTTP: 라벨이 없으므로 FPR·precision·recall은 null이다. 0% flag인 기준선도 완벽한 모델이라는 뜻이 아니다. 변화하는 수치 분포와 상수 특징의 IQR floor 영향이 가능하므로 정답 검토가 필요하다.
- RBD24: 시간 holdout에서 IF recall=0%, LOF≈2.64%, 지도학습≈15.59%로 공격 누락이 크다. 높은 precision만 보고 운영 채택하지 않는다. 원 window/단위 미확정과 신호를 제한한 allowlist도 한계다. test를 보고 특징을 되돌리거나 threshold를 낮추지 않았다.
- RBA: 합성 자료의 prefix 연구 결과다. ATO/attack-IP 라벨 의미를 구분하고 라벨 없는 공격 IP 행은 정답 지표에서 제외한다. 운영 IDS 적용 금지와 짧은 이력/cold start 편향을 유지한다.
- EClog: Guestbook 조건 때문에 다운로드·학습 미완료. 제공자 조건을 우회하지 않았다.

후속 개선은 새로운 개발용 시간 fold에서 특징·원단위 검증과 정상/공격 라벨 검토를 진행하고, 현재 test와 다른 최종 holdout으로 평가한다. 현 결과만으로 최종 모델을 선정하거나 자동 조치를 활성화하지 않는다.

정확한 source/hash·split 범위·cohort·분모·모델별 시간·artifact hash는 [manifest 디렉터리](manifests/)를 참조한다. raw identity/URL이나 학습 데이터·모델 파일은 Git에 포함하지 않았다.

### RBA 희소 정답의 해석

전체 prefix에 ATO는 4건, test에는 **1건**뿐이다. IF가 그 1건을 탐지해 표상 recall=100%지만 일반 성능의 근거가 아니다. 알려진 라벨 test에서 FP=452건, precision≈0.221%다. LOF·통계·지도학습은 그 1건을 놓쳤다. 알려진 test 정답 43,928개와 unknown 4,613개를 분리했고, 전체 flag 수와 confusion의 양성 예측 수가 다른 것은 unknown 때문이지 계산 오류가 아니다. 희소 양성과 짧은 prefix로 지도학습의 유효성을 입증하지 못했다.
