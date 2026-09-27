# Colab CUDA assertion·Drive 용량 복구 — STAR

## S
사용자 T4/약14.5GiB VRAM/XGBoost3.0.5/CuPy13.6 환경의 smoke는 통과했으나 첫 실제 모델에서 WQSummary/Span 인덱스 CUDA assertion 후 native abort가 발생했다. 모델 저장은 0개, wrapper 종료 후 study.json은 RUNNING으로 남았다. 별도로 prepared 배열을 실행마다 Drive에 복제해 quota 초과가 발생했다. 원인 커널의 정확한 결함/입력 조건은 아직 재현하지 못했다.

## T
VM에 남은 prepared 배열을 보존하고 다운로드·전처리·Drive 중복 복사 없이 복구한다. GPU 실패 경로를 피하면서 트리 학습/예측 CUDA 사용을 유지한다. native process abort와 백업 실패를 각각 정확히 기록한다.

## A (구현 전 계획)
- colab-gpu-v2: NumPy CPU DataIter에서 가중 QuantileDMatrix를 생성하고 CUDA hist로 학습. 샘플/가중치/분할/후보 설정은 유지한다. quantile 경로가 달라 새 profile/model ID로 분리하고 v1 snapshot은 보존한다. 공식 API가 CPU 입력 전처리 후 GPU training을 지원한다. 실제 전체 GPU 재검증 전에는 해결을 확정하지 않는다.
- smoke도 weighted CPU iterator → CUDA train/predict 경로로 바꾼다. quantile 생성 단계를 progress에 따로 기록한다.
- --prepared-local로 VM의 완성 배열 경로를 직접 사용한다(새 run 출력, checksum 검증, 기존 파일 수정 없음).
- 기본 backup-policy=results-only: 모델/연구 결과만 백업하고 배열은 기존 원본을 참조. full은 명시적으로 요청할 때만 배열 복제. local-only는 Drive에 전혀 쓰지 않고 결과를 VM에 보존하며 다운로드 필요를 알린다.
- native abort의 returncode를 wrapper가 FAILED로 기록. Drive 백업 오류가 실제 학습 실패를 덮어쓰지 않도록 로컬 실행 기록을 먼저 저장한다.
- Colab 복구 셀은 현재 VM의 배열이 있는지 확인하고 새 checkout/output/log를 사용한다. 강제 reset/삭제/Drive 파일 정리 없음. GPU 상태는 별도 새 subprocess에서 검사한다.

## R
검증 결과는 RESULTS.md에 기록한다. 로컬 Mac 학습은 계속 중단 상태.

근거: [XGBoost3.0 Python API의 CPU input → GPU training](https://xgboost.readthedocs.io/en/release_3.0.0/python/python_api.html). 사용자 로그는 결함 증거이고 작은 smoke 통과만으로 전체 데이터 성공을 주장하지 않는다.

## 복구 실행 (기존 VM 유지)

기존 fit은 native abort로 종료됐다. RUNNING 표시는 생존 증거가 아니다. 이 실행의 완료 모델은 0개다. 아래 셀은 새 checkout·새 출력 디렉터리를 만들고 기존 배열을 읽는다. Drive를 마운트하거나 쓰지 않는다. 학습 완료 후 결과 ZIP 다운로드를 요청하므로 브라우저 다운로드를 확인해야 한다. VM이 없어지면 다운로드하지 않은 결과는 유실된다.

```python
import subprocess, sys, runpy
from pathlib import Path
from datetime import datetime, timezone

prepared = Path('/content/zetty-rba-20260927-082657-588360/prepared/rba')
assert (prepared/'dataset.json').is_file(), f'기존 전처리 배열이 없습니다: {prepared}'
repo = Path('/content') / ('zetty-recovery-code-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'))
subprocess.run(['git', 'clone', '--depth', '1', '--branch', 'feature/public-data-training-star',
                'https://github.com/jjyj0203/uba-analyzer.git', str(repo)], check=True)
# 현재 세션에 v1 GPU 의존성이 설치되어 있으므로 다시 설치하지 않습니다.
sys.argv = [str(repo/'scripts/ml/recover_colab.py'), '--prepared', str(prepared)]
runpy.run_path(sys.argv[0], run_name='__main__')
```

`phase=quantile, quantile_device=cpu`는 CPU의 가중치 분위수 구성이다. 그 다음 `phase=boosting, device=cuda:0` 및 `boosting_round` 로그를 확인한다. CUDA 학습/예측이 CPU로 fallback하면 실패로 처리한다. 이 우회가 전체 데이터에서 성공했다는 주장은 실제 Colab 완료 전에는 하지 않는다.

새 Colab 세션에서는 GPU 의존성 lock을 설치하고 원본 Drive의 `20260927-full/prepared/rba`를 VM으로 복사해야 한다. results-only 백업을 `resume`할 때는 동일 데이터의 `--prepared-local`을 별도로 지정한다. 원본 체크포인트의 Python minor, 패키지 버전, 프로파일과 source snapshot 검증은 그대로 유지한다. v1 모델을 v2 완료 후보로 섞지 않는다.

## 노트북 자체 정리 — STAR (구현 전)

- S: 별도 답변의 복구 셀과 기존 노트북의 fresh/Drive 경로가 달라 복붙 시 잘못된 셀을 다시 실행할 수 있다.
- T: `notebooks/zetty_rba_colab.ipynb`를 현재 VM 복구용 최종 진입점으로 바꾼다.
- A: 독립 실행 가능한 코드 셀 하나에 환경·기존 배열 확인, 새 checkout, v2 복구 실행을 묶는다. 기본값은 현재 VM 배열·Drive 쓰기 없음이며, 완료 ZIP 다운로드는 복구 스크립트가 담당한다. 새 런타임에는 원본 배열 복원이 필요하다고 명시한다. 기존 일반 fresh/resume 노트북은 별도 이름으로 보존한다.
- R: 구현 후 구문·진입 가드 검증 결과를 RESULTS.md에 기록한다. 노트북 편집으로 실제 학습을 실행하지 않는다.
