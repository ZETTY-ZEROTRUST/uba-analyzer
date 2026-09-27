# 무료 Colab GPU 학습 — STAR

## S: 상황과 문제
기존 full CPU 연구는 n_jobs/thread limit 2로 고정되어 GPU 런타임을 사용해도 CUDA를 사용하지 않는다. RBA 약 3,127만 행의 인과적 전처리와 여러 CPU 후보 비교에 시간이 걸린다. 사용자는 무료 Colab 자원을 실제 활용하는 새 학습을 요청했다.

## T: 목표와 이유
학습/보정/검증/test 분할과 기준을 유지한 GPU 비교 버전을 추가한다. CPU 기존 실험/모델/스냅샷은 보존한다. 무료 Colab GPU의 종류/할당/연속 실행 시간을 보장하지 않으며 TPU나 유료 런타임을 전제하지 않는다.

## A: 구현 전 결정
- profile colab-gpu-v1: GPU XGBoost depth 4/6 × seed 42/2026, 각 200 rounds, hist/max_bin128; CPU IF 100trees/512samples × 같은 seeds를 기준선으로 포함. 기존 HGB/RF/LOF의 재실행을 대신하는 별도 후보군이며 같은 모델의 가속판이라고 부르지 않는다.
- GPU DataIter/QuantileDMatrix로 입력 배치 전송, GPU inplace_predict로 평가. 전체 eligible train과 전체 holdout 유지. label -1 제외·train label에서만 class weighting. validation/test로 학습하거나 조기 종료하지 않는다.
- runtime GPU smoke 검사로 CUDA 사용 증명 및 CPU fallback 차단. 할당 CPU affinity와 GPU free memory에 맞춰 작업자/배치 크기를 선택하고 기록한다. VRAM 부족 시 후보/행 수를 임의 축소하지 않는다.
- NumPy memmap 유지. 전처리 완료 배열만 백업/재사용하며 history.sqlite 등 임시 캐시는 제외. prepared 모드는 Python minor가 다른 기존 전처리도 새 연구에 사용 가능(모델 역직렬화 없음). resume은 기존 Python/package/code/profile 일치가 필요하다.
- GPU 학습 모델은 native UBJ bytes를 보존하고 CPU 추론이 가능하도록 기본 로딩 장치를 CPU로 설정한다. GPU 평가일 때만 명시적으로 CUDA 설정. RBA 피처용이며 HTTP 모델을 대체하지 않는다.
- 체크포인트는 후보별 완료 단계 단위이며 진행 중인 boosting fit은 중단 시 처음부터 다시 실행한다.

## R: 검증 결과
구현 후 실제 수행한 경량 검증과 GPU 미검증 부분을 RESULTS.md에 기록한다. 로컬 대규모 학습은 금지 상태를 유지한다.

근거: [Colab FAQ](https://research.google.com/colaboratory/faq.html), [XGBoost 3.0 GPU](https://xgboost.readthedocs.io/en/release_3.0.0/gpu/index.html), [GPU Quantile iterator](https://xgboost.readthedocs.io/en/release_3.0.0/python/examples/quantile_data_iterator.html), [CuPy 13.6](https://docs.cupy.dev/en/v13.6.0/install.html).
