# Redis 없는 파일 탐지 결과 — STAR

## S / T

사용자 지시로 Redis를 제외하고 pipeline→탐지까지만 구현했다. 준비된 feature replay에서 실제 로그 정규화·피처 계산까지 연결하되 모델 재학습은 하지 않았다.

## A — 실제 구현 및 개선

- log-pipeline owner의 producer/contract snapshot을 UBA에서 재사용한다. HMAC client/path, strict fields, checksum/capture metadata로 raw 식별자와 임의 필드를 전달하지 않는다.
- 학습 HTTP 피처 계산식을 순수 `window_features` 함수로 분리해 학습/추론이 같은 공식을 호출한다. 기존 저장 모델/threshold는 그대로 사용한다.
- 이벤트 ID/내용 충돌과 checksum 불일치는 거부한다. 중복은 집계 전에 제거한다. 입력 순서와 재실행에 관계없이 같은 detection ID를 만든다.
- capture complete/범위·최소 관측 수·bytes 누락을 검사한다. 미평가 상태에 score/flag를 채우지 않는다.
- SQLite에 결과를 transaction으로 저장하고 전체 JSONL을 임시 파일 후 replace한다. 동일 capture 재실행으로 결과가 늘지 않는다.
- Redis 서비스·Python client 의존성·publish/worker 명령을 제거했다. 단일 Docker job에 network_mode:none/CPU0.5/1GiB/thread1을 적용했다.
- 첫 테스트에서 shared producer의 __main__ snapshot 누락을 발견해 owner의 동일 파일을 포함시켰고 재검증했다.

## R — 실측

| 검증 | 결과 |
|---|---|
| log producer 단위 | 4개 통과 |
| 신규 HTTP pipeline 단위 | 6개 통과, fit 없음 |
| 기존 파일 추론 검사 | Redis 검사 제거 후 8개 통과, fit 없음 |
| Colab checkpoint 검사 | 3개 통과, fit 없음 |
| Docker build / 유한 추론 | 성공, Redis·네트워크 사용 없음 |
| 합성 raw 로그 | 206행 → 중복1 제거 → 이벤트205개 |
| 5분 관측 | 4개: EVALUATED2 / INSUFFICIENT_DATA1 / INCOMPLETE_WINDOW1 |
| 정상형2요청 | score0.5906625424, threshold0.6994570174, flag=false |
| 버스트200요청/400MB | score0.7152130445, 같은 threshold, flag=true |
| 누락/저활동 | score/flag=null |
| Mac와 Docker 결과 | 해당 fixture score/flag 일치 |
| 동일 입력 재실행 | SQLite 탐지4개 유지 |

이 결과는 합성 파일 fixture로 연결을 검사한 것이다. 두 평가 구간의 성공을 실제 공격 탐지율/FPR/서비스 성능으로 표현하지 않는다. Online Shop 모델은 정답이 없어 명시적 IF 후보를 사용했으며 실서비스 최적 모델을 선택했다고 하지 않는다.

원본 학습의 최종 평가179개와 RBA validation11개는 그대로 보존했다. 로컬 RF/final test를 재개하지 않았다. 현재 이미지에는 Redis client가 설치되지 않는다. 과거 Redis 컨테이너는 중지 상태이며 신규 Compose에는 해당 서비스가 없다.

## 남은 연결

Claude가 실제 Nginx log_format과 수집 파일 경로를 적용하면 같은 CLI로 파일을 처리할 수 있다. 실제 server log로의 검증과 인증된 사용자 attribution은 아직 하지 않았다. 정책·Auth 조치는 최신 사용자 지시대로 제외했다. Colab 계정 인증·업로드·원격 학습 실행은 사용자가 노트북에서 진행해야 한다.

## Git 연결

[로그 생산기 PR #2](https://github.com/ZETTY-ZEROTRUST/log-pipeline/pull/2), [UBA PR #4](https://github.com/ZETTY-ZEROTRUST/uba-analyzer/pull/4)는 develop 대상이다. 원본 READ 권한으로 직접 병합할 수 없어 PR 상태를 유지한다. main 배포 workflow를 변경하거나 실행하지 않았다.
