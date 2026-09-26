# 실험 추론 연결 결과 — STAR

## S — 실제 문제

Mac CPU 94°C 보고로 RBA 학습을 중단했다. 기존 v1 runtime에는 새 공개 모델을 사용할 경로가 없고, 학습 run의 threshold는 joblib 내부가 아니라 study.json에 분리돼 있었다. 임의의 모델 파일만 mount하면 source/전처리/threshold가 어긋날 수 있었다.

## T — 목표

추가 로컬 학습 없이 이미 완료한 모델을 사용하는 제한된 실험 pipeline을 제공한다. 모델과 입력의 의미·버전을 확인하고, 결과 저장/ACK 사이 장애에도 중복 탐지 결과를 만들지 않는다. Colab으로 남은 학습을 넘길 수 있게 보관·안내를 준비한다.

## A — 구현 및 문제 개선

- `zetty_uba.lab`: export → JSONL producer → Redis Stream → pinned model inference → SQLite detection+receipt → ACK. CLI는 구 pipeline.py를 import하지 않는다.
- model loader: 신뢰한 로컬 study manifest hash, artifact hash, package version, source/feature 순서/version, plan hash, threshold 규칙을 확인한다. manifest/threshold 없는 단독 joblib 사용을 거부한다.
- 입력은 엄격한 public-replay schema다. label/임의 필드는 거부하며 feature 결측·유한값·source/version을 검사한다. FEATURE_MISMATCH/MODEL_UNAVAILABLE에서는 score/flag가 null이다.
- 동일 observation ID/내용은 동일 결과를 재사용한다. ID/내용 충돌은 격리한다. SQLite commit 후 ACK하며 저장 실패는 ACK하지 않는다.
- Docker worker CPU0.5/1GiB·thread1, Redis CPU0.25/192MiB, 포트 비공개, 모델/입력 read-only, 결과 volume 보존, 유한 처리 후 종료로 구성했다.
- Docker 소켓 접근이 샌드박스에서 거부돼 승인된 Docker 도구 권한으로 실행했다. 기존 backend 서비스·DB에는 접속하지 않았다.
- Colab backup은 artifact를 복사한 뒤 study/dataset commit marker를 마지막에 교체한다. 복사 실패 시 새 manifest가 미완료 파일을 가리키지 않도록 수정했고 fixture로 확인했다.

## R — 실제 검증

| 검사 | 결과 |
|---|---|
| inference-only 단위 검사 | 9개 통과, fit 없음 |
| Colab backup/로컬 실행 거부 검사 | 3개 통과, fit 없음 |
| notebook JSON/code cell compile | 통과, 셀 실행 없음 |
| 로컬 Mac 저장 모델 추론 | 40건 EVALUATED |
| Docker image build / Compose config | 성공 |
| Docker producer→Redis→worker→SQLite | 40건 전달·40개 탐지 결과 |
| 같은 40건 재전달 + commit 후 ACK 전 종료 주입 | 주입된 종료 exit1 확인, 재시작 후 회수 성공 |
| 최종 SQLite | 탐지 40개, EVALUATED receipt 80개 |
| 최종 Redis pending | 0건 |
| 전용 lab 컨테이너 | 검증 후 중지 |
| 보관 | public data/prepared/run/log 572개 파일 checksum 검증 후 ZETTY 보관 |

실제 사용 모델은 완료 run `Phishing_smartphone-expanded`의 validation 선택 `hgb200-leaf31-v2`다. 40건은 균등 test 표본+공격 행 일부로 만든 통합 smoke이며 정상16/공격24다. 이 비율과 탐지 flag를 전체 공격 성능으로 보고하지 않는다. 전체 test 성능은 07의 기존 179개 평가를 따른다.

검증 명령과 사용법은 [RUNBOOK](RUNBOOK.md)에 있다. 전체 학습 테스트는 model.fit을 호출하므로 발열 중단 이후 다시 실행하지 않았다. 기존 23개 학습 테스트 통과 기록은 이전 단계 결과이며 이번에는 위 12개 inference/checkpoint 검사만 새로 실행했다.

## 실제로 남은 범위

- RBA RF와 전체 final test는 중단 상태다. [Colab 실행 안내](../09-colab/HOWTO.md)를 따른다.
- Colab 계정/Drive 인증·업로드·원격 runtime 실행은 아직 수행하지 않았다.
- C-02 서비스 이벤트, 검증 actor의 HTTP 집계, ES 저장, backend/Auth 집행은 이 공개 replay와 별도다. 구 서비스 entrypoint를 새 경로로 전환했다고 보고하지 않는다.
- original repo는 현재 계정 READ 권한으로 develop 병합이 불가능하다. 포크 PR에 코드/문서/검증을 반영하며 실제 병합 완료로 표시하지 않는다.
