# 실험 UBA 실행 안내

모든 명령은 `/Users/jjyj2302/zetty/uba-training`에서 실행한다. 학습 명령은 없다. 기본 모델은 완료된 Phishing smartphone 연구에서 validation으로 선택한 `hgb200-leaf31-v2`다. 다른 source의 이벤트를 넣으면 FEATURE_MISMATCH다.

## 1. 현재 저장 결과 확인

```bash
/Users/jjyj2302/zetty/.venv/bin/python scripts/ml/inspect_study.py \
  /Users/jjyj2302/zetty/ml-runs/20260927-full/runs
```

`EVALUATED`: 최종 test 완료, `VALIDATED`: validation까지 완료, `STOPPED_BY_USER`: 중단. 학습을 실행하지 않고 JSON만 읽는다. 전체 비교는 [CSV](../07-full-data-study/comparison.csv), [결과](../07-full-data-study/RESULTS.md)를 본다. 같은 source 안에서 recall/precision/FPR와 분모를 함께 비교한다.

## 2. 읽기 전용 모델·입력 경로 설정

검증된 replay 40건과 환경 파일은 `/Users/jjyj2302/zetty/ml-lab/20260927`에 보관한다. 공개 benchmark 관측이며 실제 로그인 이벤트가 아니다. 테스트를 위해 공격 행 일부를 포함해 추출했으므로 이 40건의 비율을 전체 성능으로 보고하지 않는다.

```bash
export ZETTY_LAB_RUN=/Users/jjyj2302/zetty/ml-runs/20260927-full/runs/Phishing_smartphone-expanded
export ZETTY_LAB_INPUT_DIR=/Users/jjyj2302/zetty/ml-lab/20260927
export ZETTY_LAB_MANIFEST_SHA256=03979c5639de8e683adc5a292ea824919ba63644e4acef2b8a43e43eddc647f7

docker compose -f docker/lab/compose.yaml config --quiet
docker compose -f docker/lab/compose.yaml build uba
```

모델은 Docker 이미지에 넣지 않고 read-only로 mount한다. manifest는 별도로 신뢰한 hash로 고정한다. 모델/manifest가 외부에서 임의로 전달된 경우 checksum만 맞다고 신뢰하지 않는다. runtime 의존성은 학습 버전과 일치해야 한다.

## 3. 입력 전달 → 추론 → 결과 확인

```bash
docker compose -f docker/lab/compose.yaml up -d redis-lab
docker compose -f docker/lab/compose.yaml run --rm uba publish --input /input/replay.jsonl
docker compose -f docker/lab/compose.yaml run --rm uba
docker compose -f docker/lab/compose.yaml run --rm uba inspect --database /state/results.sqlite
```

worker는 최대 1,000 delivery 또는 10초 유휴 후 종료한다. CPU는 0.5, 메모리는 1GiB, 내부 수치 라이브러리 thread는 1이다. 별도 Redis는 CPU0.25, 192MiB, 포트 비공개/내부 network다. producer는 최대 10,000건 제한이며 원본 JSONL을 보존해 재전달할 수 있다. stream을 무한히 넣는 장기 서비스로 쓰지 않는다.

출력은 `zetty-uba-lab_results-lab` volume의 SQLite `detections`와 `receipts`다. 탐지 결과에는 모델·입력 hash, score/threshold, is_anomaly, status, 관찰/검토 policy가 있다. 결과+receipt commit 후 ACK한다. SQLite 실패 시 ACK하지 않는다. 잘못된 입력은 raw payload 없이 hash/이유를 저장한 후 격리 처리한다.

## 4. 결과 행 읽기

```bash
docker compose -f docker/lab/compose.yaml run --rm --entrypoint python uba -c \
'import sqlite3,json; c=sqlite3.connect("file:/state/results.sqlite?mode=ro",uri=True); print(json.dumps([json.loads(r[0]) for r in c.execute("select payload from detections limit 5")],indent=2))'
```

동일 observation 재전달은 결과 수를 늘리지 않고 receipt만 추가한다. 같은 ID의 내용이 달라지면 ID_CONFLICT다. 모델 revision을 바꾸면 별도 탐지 결과를 만든다. 같은 모델 revision에서 MODEL_UNAVAILABLE로 기록된 결과는 자동 재평가하지 않으며, 원인을 수정하고 새 모델/실행 revision으로 명시적으로 재실행한다.

## 5. 종료

```bash
docker compose -f docker/lab/compose.yaml stop
```

이 전용 Compose만 종료하며 기존 backend/DB 컨테이너에는 영향을 주지 않는다. 볼륨과 모델은 유지된다. 검증 종료 후 전용 Redis도 중지했다. 재학습·cron·자동 재시작은 구성하지 않았다.

## Colab 결과로 교체

Colab `COMPLETED` run을 새로운 디렉터리에 보관하고 `study.json` hash를 확인해 `ZETTY_LAB_RUN`과 `ZETTY_LAB_MANIFEST_SHA256`을 함께 변경한다. RBA 모델에는 RBA feature_version/names와 일치하는 replay가 필요하다. RBD 입력을 RBA 모델에 재사용하지 않는다. 무라벨 source의 모델은 worker 명령에 `--model <id>`로 명시한다.

현재 이 명령은 공개 자료의 source-specific feature observation을 사용한다. C-02 SecurityEvent serializer/인증된 actor/HTTP 집계/ES/Auth 집행은 별도 통합 단계이며 현재 pipeline.py의 v1 실행을 바꾸지 않았다.
