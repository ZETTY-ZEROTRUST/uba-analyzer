# Redis 없는 pipeline 실행

작업 경로: `/Users/jjyj2302/zetty/uba-training`. 학습은 실행하지 않는다. 완료된 Online Shop `if-t100-s512-seed42` 모델을 명시적으로 사용한다. label 없는 공개 모델의 전이 실험이며 실제 계정이나 공격 분류기가 아니다.

## 준비된 데모 실행

데모 capture와 결과는 `/Users/jjyj2302/zetty/ml-file-pipeline/20260927`에 보관한다.

```bash
cd /Users/jjyj2302/zetty/uba-training
export ZETTY_LAB_RUN=/Users/jjyj2302/zetty/ml-runs/20260927-full/runs/online-shop
export ZETTY_LAB_INPUT_DIR=/Users/jjyj2302/zetty/ml-file-pipeline/20260927/capture
export ZETTY_LAB_OUTPUT_DIR=/Users/jjyj2302/zetty/ml-file-pipeline/20260927/results
export ZETTY_LAB_MANIFEST_SHA256=2780763b7555698826adbf2ee389c10499b98326c9fcf1b821bfb27fcec3190c
export ZETTY_LAB_MODEL=if-t100-s512-seed42

docker compose -f docker/lab/compose.yaml config --quiet
docker compose -f docker/lab/compose.yaml build uba
docker compose -f docker/lab/compose.yaml run --rm uba
```

**Redis 서비스·클라이언트 없음.** worker daemon도 없다. network_mode:none, CPU0.5·RAM1GiB·thread1, 모델/입력 read-only mount이며 파일 처리 후 종료한다. 다른 backend/인프라 컨테이너를 시작하거나 변경하지 않는다.

Docker 없이 실행하려면 다음을 사용한다.

```bash
PYTHONPATH=src:vendor/log-pipeline/src OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
  /Users/jjyj2302/zetty/.venv/bin/python -m zetty_uba.lab.http_file \
  --capture "$ZETTY_LAB_INPUT_DIR" --run "$ZETTY_LAB_RUN" \
  --manifest-sha256 "$ZETTY_LAB_MANIFEST_SHA256" \
  --model "$ZETTY_LAB_MODEL" --output "$ZETTY_LAB_OUTPUT_DIR"
```

## 결과 읽기

- `summary.json`: 처리 행/구간 수, 품질 상태별 수, 이상 표시 수.
- `detections.jsonl`: 구간별 model score/threshold, flag, 관측 client, 근거/품질, model/input hash.
- `detections.sqlite`: 같은 ID를 다시 저장하지 않는 결과 원본. JSONL은 DB 전체를 원자적으로 내보낸다.

`EVALUATED`만 score/flag가 있다. `INCOMPLETE_WINDOW`와 `INSUFFICIENT_DATA`는 null이다. 누락을 정상으로 읽지 않는다. `is_anomaly=true`는 모델 기준 이상이며 공격 확정이 아니다. 이 실행에는 정책·인증 조치가 없다.

같은 capture를 다시 실행해도 detection 수는 늘지 않는다. capture 범위/완전성/실제 이벤트 또는 모델 revision이 바뀌면 새 input version으로 결과를 만든다. 기존 결과는 삭제하지 않는다.

## 새 합성 데모 생성

```bash
PYTHONPATH=src:vendor/log-pipeline/src /Users/jjyj2302/zetty/.venv/bin/python \
  scripts/ml/make_http_fixture.py --output /path/to/new-demo
```

합성 로그일 뿐 실제 서버에 공격을 보내지 않는다. 206행에 정상·버스트·누락·저활동·중복 사례가 있다. ephemeral HMAC key는 메모리에서만 사용한다. 생성된 demo/capture를 입력 디렉터리로 지정한다.

## 실제 Nginx 로그 연결

`log-pipeline`의 `nginx/http-observation-format.conf`를 Claude가 인프라 설정에 적용해야 한다. request_id/time/remote_addr/user_agent/method/uri/status/body_bytes만 기록하고 Authorization/Cookie/query/body를 넣지 않는다. 원문 로그는 생산기에서 HMAC client/path로 변환하고 UBA에는 가명 capture만 전달한다.

[생산기 저장소 실행 안내](https://github.com/jjyj0203/log-pipeline/blob/feature/file-http-observations/docs/10-file-pipeline/RUNBOOK.md)를 따른다. 현재 제공된 코드 snapshot은 `vendor/log-pipeline/SOURCE.json`의 원본 commit/hash와 같다. snapshot을 독립 수정하지 않는다.

완전성은 capture 시작/끝과 누락 여부를 호출자가 확인해야 한다. 기본은 incomplete이며 `--complete`는 확인된 capture에만 사용한다. UTC `[start,end)` 5분 집계, 최소2건, response bytes 필수다. 피처 공식은 학습과 같은 `online_shop.window_features`를 사용하며 순서·스케일·threshold를 새로 fit하지 않는다.

## 모델과 Colab

[현재 179개 최종 평가 확인](../07-full-data-study/RESULTS.md), [Colab 남은 학습 안내](../09-colab/HOWTO.md)를 따른다. 이 HTTP pipeline에 RBA/RBD 모델을 넣으면 source/feature 검사를 거부한다. RBA 체크포인트와 현재 HTTP 추론 환경은 서로 다른 관측 단위다. 로컬 모델 학습은 중단 상태다.
