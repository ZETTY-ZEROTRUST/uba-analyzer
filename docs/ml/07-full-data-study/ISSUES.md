# 전체 학습 중 문제와 개선 — STAR 기록

## 1. Phishing smartphone 보정 표본 부족

**S:** 원본42,974행에서 충돌1,152행을 제외했다. 최초50/15/15/20 unique-time 분할과24시간 embargo 이후 calibration은197행이며 label0가95개라 최소100개 조건에 실패했다. 모델 fit/test에 들어가기 전의 품질 검사 실패다.

**T:** 미확인/공격 행을 정상으로 바꾸거나 embargo를 없애지 않고 충분한 보정 reference를 확보한다.

**A — 수정 전 결정:** 해당 source만 첫 경계를50%→40%로 앞당겨40/25/15/20으로 확장한다. validation/test 경계와24시간 embargo는 그대로 두고 별도 version/run으로 실행한다. 이 결정은 모델 성능을 보고 선택한 것이 아니라 calibration 표본 부족의 수정이다. 원래 실패 run을 보존하고 보정 확대 후의 분모·결과를 기록한다. 다른 source에 같은 변경을 자동 적용하지 않는다.

**R:** 아래 후속 검증/실행 결과로 갱신한다.

추가 원인: 최소 표본 오류가 초기 manifest 작성 후 본 학습 try/except 앞에서 발생해 초기 run JSON에는 RUNNING이 남았다. queue와 실제 stderr는 실패를 기록했다. 최소 표본 거부 시 즉시 FAILED와 정확한 reference 수를 기록하도록 수정했고 fixture로 확인했다. 원래 run도 실제 stderr 근거로 FAILED로 정정했다.

검증: 보정 구간을 늘려도 validation/test 행 인덱스가 그대로인 시험, 부족한 표본의 FAILED 기록 시험을 포함해 총23개 테스트가 통과했다.

### 보정 수정 결과

확장 run은 calibration reference 3,156개를 확보했고 14개 후보를 최종 평가했다. train16,580/calibration4,040/validation3,708/test4,661이며 validation/test 경계는 그대로다. validation 선택은 hgb200-leaf31-v2였다.

## 2. 발열에 따른 사용자 중단

S: RBA RF fit 도중 사용자가 CPU94°C를 보고했다. T: 로컬 CPU 부하를 멈추고 완료 결과를 보존한다. A: 학습 관련4개 프로세스를 종료하고 후속 조회에서0개를 확인했다. queue/study를 STOPPED_BY_USER로 정정했다. R: 179개 최종 평가와 RBA11개 validation을 보존했다. 로컬 자동 재개 없이 Colab checkpoint와 추론 환경을 준비한다. 실제 하드웨어 온도를 도구로 측정한 것은 아니며94°C는 사용자 보고다.
