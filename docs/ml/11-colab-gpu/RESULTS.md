# 구현 결과와 검증 범위

## 변경

- 노트북 기본값 colab-gpu-v1/fresh. 실제 할당 GPU 검사 → 고정 GPU 패키지 설치 → tiny CUDA fit/predict 확인 → Drive 연결 → 전체 RBA 준비/학습/평가.
- XGBoost depth4/6 × rounds200/400 GPU 후보 4개, IF seed42/2026 CPU 기준선 2개. 기존 cpu-full 14개 후보는 선택 가능하며 과거 모델은 보존.
- CuPy 배치 → QuantileDMatrix → GPU hist → GPU inplace_predict. CPU fallback 검사. CPU affinity(최대8)/free VRAM 기반 실행 자원 및 batch 기록. 불필요한 전체 scaler pass 생략.
- prepared 모드에서 검증된 배열만 재사용. 백업에서 history.sqlite 등 scratch 제외, 메타데이터는 배열 복사 후 게시. download/preparation/backup 및 fit/evaluation 시간 분리 기록.
- 모델은 native UBJ bytes를 포함하며 로딩 기본 장치는 CPU. CUDA는 GPU 평가 시에만 재설정. RBA 추론의 XGBoost version 검사를 추가했다.

## 수행한 검증

- GPU 계약/백업/모의 연구 흐름 **9개**: 후보/자원, CPU fallback 차단, CPU 로딩, train-only batch/가중치, scratch 제외/손상, 전체 holdout/완료 재실행, GPU 미할당 사전 중단, CPU↔GPU profile 혼합 금지, GPU score 경로.
- Colab checkpoint **7개**, 기존 inference **8개**, HTTP 파일 pipeline **6개**, 시간 분할/selection/누락/실패 순수 테스트 **5개** 통과. 합계 **35개**, 실제 estimator fit은 mock 처리했다.
- 노트북 모든 코드 셀/관련 Python 소스 구문 검사와 git diff --check 통과.
- PyPI 메타데이터에서 XGBoost3.0.5, CuPy-CUDA12x13.6.0, fastrlock0.8.3, NCCL-CUDA12 2.27.7의 Python3.13 Linux wheel 및 전이 의존성을 확인했다. CPU lock 6개도 유지한다.

## 아직 검증하지 않은 것

로컬 Mac에 CUDA가 없고 로컬 학습 중단 지시가 유지되어 실제 GPU fit/속도/대규모 VRAM peak/Colab 설치는 실행하지 않았다. 모의 테스트 통과를 GPU 실행 성공으로 보고하지 않는다. Colab의 첫 GPU smoke, 그 다음 전체 데이터 실행이 필요하다. GPU가 모든 단계를 가속하지 않는다. 인과적 전처리/Drive/IF는 CPU·I/O 작업이며 무료 GPU 가용성은 보장되지 않는다. 새 후보군의 전체 소요 시간을 이전 14후보 CPU 연구와 비교해 같은 모델의 GPU 가속 배수라고 주장하지 않는다.
