# 전체 자료 실험 — 중단 시점의 실제 결과

## S / T

부분 자료에서 전체 자료·다중 모델 비교로 확장했다. 14개 source/task와 최대 14개 후보를 각각 분리했다. 구현 전 계획은 README, 품질 문제와 개선은 ISSUES에 있다.

## A — 수행과 중단

Online Shop 및 RBD24 12개 파일은 전체 처리·최종 평가를 완료했다. RBA CSV 31,269,264행을 EOF/CRC까지 확인하고 1,526개 결측을 제외한 31,267,738개 행을 준비했다. 전처리는 1,243.448초였다. 이후 11개 모델의 학습·보정·validation을 완료했다.

사용자가 CPU 온도 94°C를 보고하고 전부 중단을 지시했다. 마지막 Random Forest fit 중 관련 프로세스 4개를 종료했고 후속 조회에서 학습 프로세스 0개를 확인했다. 자동 재시작하지 않는다. RBA 최종 test/모델 선택은 아직 없으며 완주 결과로 보고하지 않는다.

## R — 보존된 결과

최종 평가 완료 179개(Online Shop 11 + RBD 168), validation 완료 RBA 11개. EClog는 필수 Guestbook 정보가 없어 미학습이다.

| Source | 상태 | 최종 평가 | validation만 완료 | 생략 | validation 선택 |
|---|---|---:|---:|---:|---|
| Crypto_desktop | COMPLETED | 14 | 0 | 0 | hgb200-leaf31-v2 |
| Crypto_smartphone | COMPLETED | 14 | 0 | 0 | hgb100-leaf15-v2 |
| NonEnc_desktop | COMPLETED | 14 | 0 | 0 | rf100-depth12-v2 |
| NonEnc_smartphone | COMPLETED | 14 | 0 | 0 | rf100-depth12-v2 |
| OutFlash_desktop | COMPLETED | 14 | 0 | 0 | hgb200-leaf31-v2 |
| OutFlash_smartphone | COMPLETED | 14 | 0 | 0 | hgb200-leaf31-v2 |
| OutTLS_desktop | COMPLETED | 14 | 0 | 0 | hgb200-leaf31-v2 |
| OutTLS_smartphone | COMPLETED | 14 | 0 | 0 | hgb100-leaf15-v2 |
| P2P_desktop | COMPLETED | 14 | 0 | 0 | hgb200-leaf31-v2 |
| P2P_smartphone | COMPLETED | 14 | 0 | 0 | rf100-depth12-v2 |
| Phishing_desktop | COMPLETED | 14 | 0 | 0 | sgdocsvm-linear-v2 |
| Phishing_smartphone-expanded | COMPLETED | 14 | 0 | 0 | hgb200-leaf31-v2 |
| online-shop | COMPLETED | 11 | 0 | 3 | 미선정 |
| rba | STOPPED_BY_USER | 0 | 11 | 0 | 미선정 |

## 해석

- [모든 후보 비교 CSV](comparison.csv)와 manifests에서 지표·분모·confusion·Wilson95·seen/unseen·설정·시간·hash를 확인한다. NOT_COMPLETED는 실패한 성능 지표가 아니라 미실행/중단 상태다.
- RBA exact LOF 두 후보는 사전 계산 예산상 제외 대상이며 해당 단계에 도달하기 전에 중단했다. Random Forest는 완료 artifact가 없다.
- RBD 12개 파일 중 20개 파일 쌍이 user/entity/time을 공유하며 고유 조합은 576,800개다. task별 결과를 독립 표본처럼 합치지 않는다.
- RBA validation ATO는 6개뿐이며 아직 최종 평가가 없다. 검증 recall 50%를 서비스 성능이나 최종 우승 근거로 삼지 않는다.
- RBD 선택 모델도 여러 task에서 낮은 recall을 보인다. 선택은 validation 규칙의 결과이며 모든 공격 탐지에 우수하다는 뜻이 아니다.
- Online Shop은 label이 없으므로 flag rate를 FPR로 부르지 않는다. 공개 자료 결과와 로컬 통합 smoke 결과를 분리한다.
- 모델/전처리/threshold는 source별이다. v1과 v2는 자료·분할·baseline이 달라 동일 조건 개선으로 해석하지 않는다.

## 다음 단계

로컬 학습 재개 없이 [실험 추론 환경](../08-lab-inference/README.md)을 구현한다. 남은 학습은 [Colab 전용 안내](../09-colab/README.md)로 옮기며 클라우드 실행 여부를 별도로 기록한다.
