> **대체됨:** 최신 사용자 지시로 Redis/정책/인증 연결을 제외했다. 현재 구현은 [10 파일 pipeline](../10-file-pipeline/README.md)이다. 아래는 이전 실행 전 계획을 보존한 것이다.

# 학습 모델의 실험용 UBA 파이프라인 — 실행 전 STAR

2026-09-27, 사용자 지시: 운영 목적이 아니며 전체 학습이 끝난 후 UBA/Docker/파이프라인 변경을 진행한다. 아래는 구현 전 계획이다. 이후 CPU 94°C 보고로 학습을 중단했고, 사용자가 학습을 멈춘 채 환경 구성을 먼저 진행하도록 순서를 변경했다.

## S — 상황

공개 자료의 source별 모델·전처리·threshold가 있지만 기존 pipeline.py는 v1 ES/7-factor/LLM 경로다. C-02 service schema/fixture와 새 producer가 없어 공개 데이터를 실제 검증 사용자 이벤트인 것처럼 넣을 수 없다. 실험 결과를 실제 프로세스·컨테이너로 재현할 진입점이 필요하다.

## T — 목표와 이유

학습한 모델을 재사용하는 연구용 replay→Redis→UBA inference→SQLite 결과/receipt 파이프라인을 만든다. 공개 자료별 특징 의미와 모델 버전을 그대로 보존하고 실제 공격 label은 탐지 입력 밖의 평가 근거에만 둔다. RBA/RBD 정답 기반 평가와 Online Shop 무라벨 관측을 구분한다. 연구용 pipeline 계약은 `zetty-lab-observation/1`이며 C-02 SecurityEvent의 대체 계약으로 선언하지 않는다.

## A — 구현 순서

1. 완료 study/선택 모델의 artifact SHA256·feature 순서·version·source·threshold를 검증하고 신뢰한 로컬 run만 로드한다. 선택 모델이 없는 source는 명시적 model ID를 요구한다.
2. 준비된 공개 자료의 test 구간에서 제한된 관측을 JSONL로 내보낸다. 이는 통합 smoke 표본이며 전체 최종 성능은 07의 전체 holdout 결과를 따른다. label을 inference payload에 넣지 않는다.
3. JSONL producer가 Redis Stream에 전달하고 UBA consumer가 새 모델을 한 번 로드해 추론한다. 입력 schema·source·feature·유한값·시간·ID를 검사하고, 모델/특징 오류는 score=null인 미평가로 기록한다. 추론 score를 공격 확률이라 부르지 않는다.
4. SQLite에 결정론적 detection ID와 입력 hash, 결과·receipt를 같은 transaction으로 저장한 후 XACK한다. 동일 입력 재처리는 동일 결과이며 같은 ID/다른 내용은 거부한다. 저장 실패는 ACK하지 않고 pending을 재처리한다.
5. 실험 policy는 관찰/검토 필요 상태만 기록한다. Auth/BFF 조치 endpoint·실계정·외부 알림 호출은 이번 입력에 존재하지 않는다.
6. 명시적 lab Compose 진입점으로 Redis와 CPU 한 개 제한의 UBA worker를 실행한다. 모델·입력은 read-only mount, 결과 volume은 지속 보관, AWS/LLM 없이 실행한다. 기존 서비스 entrypoint 전환은 C-02 연결 검증 이후다.

## 예상 문제와 개선

- 서로 다른 task/feature를 잘못 연결 → strict source/version/name/order 검사, 미평가 상태.
- pickle/joblib 실행 위험 → 임의 업로드 API 없이 관리자가 지정한 trusted run과 별도로 지정한 manifest SHA256 검사, artifact checksum 검사. checksum만으로 외부 파일을 신뢰하지 않는다.
- 재시작/ACK 유실 → SQLite 결과+receipt commit 후 ACK, pending 회수, ID 충돌 거부.
- 실험 표본을 전체 성능으로 오해 → export 범위와 count를 기록하고 전체 모델 비교와 통합 smoke를 분리.
- 노트북 발열 → 전체 재학습 없이 저장 모델 재사용, 추론 worker CPU1·메모리 상한, 유한 건수 처리 후 종료.

## R — 아직 미실행

구현·단위 검사·실제 Docker 왕복·재처리 결과를 RESULTS.md에 기록한다. C-02 서비스 이벤트, 실제 backend producer, ES 저장, 계정 조치는 이 replay 검증과 별도로 남는다.

## 구현 직전 변경 — 발열로 로컬 학습 중단

학습 관련 프로세스 4개를 종료하고 후속 조회에서 남은 학습 프로세스 0개를 확인했다. Online Shop/RBD 179개 모델은 최종 평가 완료, RBA 11개는 validation 완료이며 마지막 RF와 최종 test는 미완료다. RBA 실행 상태를 STOPPED_BY_USER로 정정했다. 재학습 없이 완료된 RBD 모델로 추론 smoke를 진행하고, Colab 전용 노트북을 추가한다. 로컬에서는 새 모델 fit을 호출하는 기존 전체 테스트도 실행하지 않는다.
