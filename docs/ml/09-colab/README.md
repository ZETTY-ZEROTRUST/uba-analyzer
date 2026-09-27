> 최신 기본 실행은 [무료 Colab GPU 실행 안내](../11-colab-gpu/RUNBOOK.md)를 따른다. 아래 과거 CPU 연구 재개 설명과 새 GPU 연구를 구분한다.

# Colab 이전 — 실행 전 STAR

## S — 상황

Mac에서 RBA Random Forest 학습 도중 사용자가 CPU 94°C를 보고해 모든 학습 프로세스를 종료했다. Online Shop/RBD 179개 최종 평가와 RBA 11개 validation 모델, 전체 RBA 전처리 배열이 남아 있다.

## T — 이유와 범위

남은 RBA 학습·최종 평가를 Google이 제공하는 원격 Colab runtime에서 수행한다. Mac의 local runtime에는 연결하지 않는다. 이미 완료한 179개 실험은 다시 학습하지 않는다. Colab에서 실제 실행·결과 생성이 확인되기 전까지 '이전 학습 완료'라고 보고하지 않는다.

## A — 두 실행 경로

[노트북](../../../notebooks/zetty_rba_colab.ipynb)을 Colab에서 연다. 셀의 경로와 mode를 확인한 후 실행한다. Python 3.12/3.13·동일 고정 의존성을 지원한다. resume은 checkpoint와 같은 Python minor가 필요하다. 기존 cpu-full은 CPU 구현이다. 새 colab-gpu-v1은 CUDA를 사용한다.

- `resume`: 준비한 checkpoint 디렉터리를 Drive에 업로드하고 경로를 지정한다. prepared/rba, runs/rba 및 source_snapshot을 읽는다. 완료된 11개 모델을 재사용하고 중단된 RF fit부터 다시 실행한 뒤 모델 선택·전체 최종 평가를 진행한다. 미완료 RF의 트리 단위 재개는 지원하지 않는다. 원본 snapshot을 별도 PYTHONPATH로 사용해 code/plan hash를 유지한다.
- `fresh`: 대용량 checkpoint 업로드를 피하려면 공식 RBA ZIP을 Colab에서 직접 받아 전체 전처리와 RBA 연구를 새 버전으로 실행한다. 기존 Mac의 11개 RBA 모델도 다시 학습하므로 resume와 구분한다. 다른 완료 source 13개는 재학습하지 않는다.

Drive checkpoint는 로컬 Colab 디스크로 복사해서 실행한다. 모델 작업 중 단계별 산출물은 Drive로 주기적으로 백업한다. 각 저장은 임시 파일 후 replace하며 원본 Mac run은 덮어쓰지 않는다. VM 중단 시 진행 중 fit은 재실행될 수 있다.

## 예상 문제와 개선

- Colab 가변 자원·VM 종료 → 완료 단계 backup, 원자료 영구 보관, 단계별 상태 확인. 무료 자원은 실행 지속 시간·RAM을 보장하지 않는다.
- Mac/Linux 환경 혼동 → 원래 환경과 cloud segment를 execution history로 함께 기록한다. cross-platform model load/score는 실제 실행 시 검증된다.
- runtime Python/의존성 불일치 → 설치·학습 전에 fail-fast; 임의 다른 버전으로 조용히 로드하지 않는다.
- 대용량 Drive I/O → 최초 local disk 복사, 결과만 주기적 백업. 업로드 없이 fresh 경로도 제공한다.
- 비용/계정 선택 → notebook 준비 자체는 유료 runtime 구매나 계정 인증이 아니다. Colab 계정의 runtime 연결과 Drive 승인은 사용자 세션에서 필요하다.

## R — 현재

노트북 및 재개 코드를 준비하는 단계다. **Colab runtime 연결·업로드·학습 실행은 아직 하지 않았다.** 로컬 학습은 중단 상태를 유지한다. 코드 검증은 notebook JSON/구문 및 inference-only 검사로 제한한다.

공식 근거: [Colab FAQ](https://research.google.com/colaboratory/faq.html), [Compose service resource limits](https://docs.docker.com/reference/compose-file/services/).

Python 3.13에서는 기본값 `MODE = 'fresh'`로 새 RBA 학습을 실행한다. 3.12 checkpoint를 3.13에서 재개하지 않는다. 기존 Colab 사본은 자동 갱신되지 않으므로 최신 노트북을 다시 열고 새 런타임에서 시작한다. [수정 과정](PYTHON313.md).
