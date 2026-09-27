# 검증 결과

2026-09-27 구현 완료. 실제 T4 전체 학습의 재성공은 아직 확인하지 않았다.

- GPU contract·Colab checkpoint·복구 wrapper: 20개 통과. CUDA/XGBoost fit은 mock이며 실제 로컬 학습 없음.
- 기존 lab inference 8개 + 시간 분할·검증 선택·unknown·calibration·실패 기록 5개 통과.
- HTTP/file pipeline 6개 통과. 첫 실행은 zetty_log PYTHONPATH 누락으로 import 실패했고, log-file-pipeline/src를 추가한 실행에서 통과.
- 합계 39개. notebook 코드 셀 compile 및 스크립트 AST, git diff --check 통과.
- v2 quantile에 CuPy.asarray가 호출되면 테스트가 실패하도록 검사. train-only indices, balanced weights, 전체 행 커버리지, CUDA booster 설정 유지.
- native child -6 → study FAILED 및 로컬 returncode -6, shell 134 검사.
- quota 실패가 학습 실패 코드나 성공한 로컬 결과를 덮지 않음 검사.
- local-only에서 백업 호출 및 Drive 디렉터리 생성 없음 검사.
- results-only에서 결과·참조만 복사, prepared 배열 중복 없음 검사.
- 기존 prepared 파일 바이트 불변 및 새 출력에 복제하지 않음 검사.

작은 GPU smoke 통과와 mock 검사는 전체 데이터 T4 성공의 증거가 아니다. 사용자 로그에 나타난 weighted GPU quantile assertion 경로를 CPU quantile로 우회하는 변경이며, 실제 원인 입력 조건/업스트림 결함은 확정하지 않았다. 학습/예측은 CUDA로 요청하고 fallback을 검사한다. CPU 분위수 구성과 GPU로의 전송 시간이 추가되므로 완료 시간은 실제 Colab 진행 로그로 판단한다.

Drive가 꽉 찬 세션의 복구는 local-only이므로 런타임 종료 전 결과 ZIP 다운로드가 필요하다. 기존 원본/백업은 삭제하지 않았다.

## 최종 복붙용 노트북

`zetty_rba_colab.ipynb`를 현재 VM용 독립 코드 셀 하나로 정리했다. 기존 일반 노트북은 `zetty_rba_colab_full.ipynb`로 보존했다. 두 파일의 코드 셀 구문 검사 통과. checkpoint/노트북 검사 9개 통과(기존 7개 + Mac 로컬 차단·배열 누락 시 subprocess 이전 중단 2개). 실제 학습·Colab 실행은 수행하지 않았다.
