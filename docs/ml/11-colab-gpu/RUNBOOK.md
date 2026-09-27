> 전체 데이터 v1 실행에서 CUDA weighted-quantile assertion이 관측되었습니다. 새 학습은 [v2 복구 절차](../12-colab-recovery/README.md)를 사용하세요. 아래는 v1 도입 시점의 기록입니다.

# Colab GPU 실행

1. 최신 `notebooks/zetty_rba_colab.ipynb`를 웹에서 열어 새 Drive 사본을 만든다. 기존 사본은 자동 갱신되지 않는다.
2. **런타임 → 런타임 유형 변경 → 무료로 제공되는 GPU**를 선택한다. T4 등이 보일 수 있지만 특정 GPU나 유료 GPU를 전제하지 않는다. 실행 중 런타임 변경은 현재 메모리 작업을 잃으므로 중간에 바꾸지 않는다.
3. 새 세션 첫 셀에서 `PROFILE = 'colab-gpu-v1'`, Python 3.12/3.13, nvidia-smi 결과를 확인한다.
4. 설치 셀은 GPU 전용 lock을 설치하고 `zetty_uba.study.gpu`의 tiny CUDA smoke fit/predict를 실행한다. `smoke: passed`, `device: cuda:0`가 나와야 한다. CUDA import/build/할당 오류는 여기서 해결하며 CPU fallback으로 진행하지 않는다. 설치 후 기존 패키지가 이미 import된 런타임이면 새 런타임에서 다시 시작한다.
5. 사용할 계정으로 Drive mount. 첫 실행은 `MODE='fresh'`. 새 학습은 공개 ZIP 다운로드·전체 전처리부터 수행한다.
6. 전처리 결과가 이미 있다면 `MODE='prepared'`, `CHECKPOINT=<prepared/rba를 담은 상위 경로>`로 전처리만 재사용한다. 기존 Mac 배열을 새 GPU 모델에 사용할 수 있으며 모델 checkpoint를 읽지 않는다.
7. 같은 GPU 연구가 중단됐으면 Drive 백업 경로를 CHECKPOINT로 지정해 `MODE='resume'` 사용. Python minor/profile/패키지/code 일치가 필요하다. 기존 CPU 모델 resume은 `PROFILE='cpu-full'` 및 해당 Python을 사용한다.
8. 4번 검사 이후 5번 실행. 후보별 fit/calibrate/validate 및 마지막 final_test가 기록된다. XGBoost 4개가 먼저 실행되고 IF 기준선 2개는 CPU로 실행한다. GPU가 놀고 있는 전처리/백업/IF 단계는 정상이다.
9. `COMPLETED`/selection/모든 평가 결과를 확인하고 ZIP을 내려받는다. 결과는 별도 실행 ID에 저장된다. XGB는 이상 탐지 비지도 모델이 아니라 RBA attack label로 학습하는 지도 모델이며 IF와 학습 방식이 다르다.

## 자원/시간

- 부동소수점 전체 입력을 VRAM에 한꺼번에 복사하지 않고 GPU QuantileDMatrix iterator를 사용한다. 배치 크기만 free VRAM으로 조정하며 데이터/후보/트리 수는 자동 축소하지 않는다. 양자화 행렬과 트리 workspace는 여전히 VRAM을 사용하므로 전체 데이터 OOM 가능성을 없앤 것은 아니다.
- CUDA smoke 성공과 대규모 전체 학습 성공은 다르다. OOM이면 에러와 stage를 보존하고, 데이터 축소 실험은 별도 버전으로 설계해야 한다.
- 전처리는 시간순 사용자 이력이므로 CPU에 남는다. 2개 스레드 고정 제한은 GPU profile에서 실제 CPU affinity(최대8)로 바뀐다.
- 완료 전처리 백업은 x/times/entities/labels.bin 및 dataset.json만 포함한다. 임시 history.sqlite/chunks/원본 ZIP은 복사하지 않는다.
- 30초 간격 후보 checkpoint 백업. 진행 중인 boosting iteration은 checkpoint하지 않으며 중단된 후보 fit은 재시작한다.
- `prepared_ready`, `prepared_backup_ready`, 모델별 fit/calibration/validation/test seconds, hardware가 기록된다. 이전 CPU 연구와 전체 시간 비교 시 후보군 변경 및 GPU/CPU 하드웨어 차이를 반드시 명시한다.

## CPU 추론

GPUBooster는 native UBJ bytes를 저장하고 reload 기본 device는 CPU다. `requirements-xgb-inference.lock`을 갖춘 별도 RBA replay 환경에서 완료 manifest/신뢰한 artifact SHA를 고정해 사용한다. CuPy는 CPU 추론에 필요하지 않다. 공개 RBA 모델은 HTTP feature와 호환되지 않는다. 현재 HTTP inference Compose에는 XGBoost 의존성을 추가하지 않는다.
