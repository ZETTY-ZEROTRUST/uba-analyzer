# 실제 실행과 재실행

ZETTY 루트의 `/Users/jjyj2302/zetty/.venv`(Python 3.12.13, arm64)를 사용했다. 사용자 장비 정보는 M1 Pro 추정·32GB이며 실제 장비명을 검증한 값이 아니다. 패키지는 `requirements-ml.lock`의 고정 버전이다. 새 artifact를 생성하는 데 외부 LLM·GPU·운영 DB 연결은 필요하지 않다.

저장소 디렉터리에서 실행한다. 아래 경로 변수는 실제 보관 위치에 맞춘다. 기존 output 디렉터리는 덮어쓰지 않으므로 재실행마다 새 이름을 쓴다.

```bash
export PYTHONPATH=src
export OMP_NUM_THREADS=2
export OPENBLAS_NUM_THREADS=2
ZETTY_PY=/Users/jjyj2302/zetty/.venv/bin/python
ZETTY_DATA=/Users/jjyj2302/zetty/ml-data/20260926
ZETTY_RUNS=/Users/jjyj2302/zetty/ml-runs/20260926

"$ZETTY_PY" -m unittest discover -s tests/ml -v
"$ZETTY_PY" -m zetty_uba online-shop \
  --input "$ZETTY_DATA/online-shop.log" --output "$ZETTY_RUNS/online-shop-rerun"
"$ZETTY_PY" -m zetty_uba rbd24-phishing-desktop \
  --input "$ZETTY_DATA/rbd24-phishing-desktop.parquet" \
  --output "$ZETTY_RUNS/rbd24-rerun" --supervised
"$ZETTY_PY" -m zetty_uba rba \
  --input "$ZETTY_DATA/rba-dataset.zip" --output "$ZETTY_RUNS/rba-rerun" \
  --max-rba-rows 250000 --supervised
```

실행 당시 staging data/run 경로는 `/private/tmp/zetty-ml-20260926/{data,runs}`였다. 최종 보관 여부는 통합 단계 결과 문서에 기록한다. 위 재실행 명령이 이미 실행됐다는 뜻은 아니다.

신규 환경에서는 Python3.12 venv를 별도로 준비하고 `python -m pip install -r requirements-ml.lock`으로 설치한다. 원자료는 source manifest URL에서 받아 CLI가 공식 size/MD5를 검증한다. 파일이 다르면 거부한다. 설치/다운로드 시간은 학습 소요 시간과 별도다.

## 모델과 이유

- RobustDistance: train 중앙값/IQR에서 가장 멀어진 특징의 거리를 사용해 복잡한 모델이 단순 통계보다 나은지 비교한다. IQR floor=1e-6이라 거의 상수인 특징에 민감한 기준선이다.
- Isolation Forest: max_samples≤512, tree200, seed42. 전체 10,000개까지 후보 reference를 학습한다.
- LOF novelty: RobustScaler(train fit), k≤35, 최대 train10,000, 예측 batch1,024. 국소 분포 이탈을 비교한다.
- HistGradientBoosting: 라벨 task의 train에 두 클래스가 있을 때만 학습한다. 100 iteration·15leaf·L2=1·early_stopping=false, train class 역빈도 weight. 최대10,000 표본을 클래스별 최대5,000으로 제한한다. 모델 class score는 보정된 공격 확률이 아니다.

실행은 동시 thread2로 제한한다. 결과는 calibration으로 정한 공통 1% tail 기준에서 비교하지만 같은 operating FPR이 보장되지는 않는다. test를 이용한 튜닝·최종 우승 모델 선정은 수행하지 않는다.

## 결과 파일

`manifest.json`에는 출처/hash·특징·split·환경·threshold·모델별 지표/시간·peakRSS가 있다. `split_indices.npz`는 adapter 처리 후 행 인덱스이며 원본 CSV 행번호가 아니다. `source_snapshot/`은 실행 당시 코드다. `*.joblib`은 이 run에서 만든 모델만 저장하며 Git에는 넣지 않는다. 외부 joblib/pickle 로더는 구현하지 않았다.

완료는 `status=COMPLETED`로 판단한다. RUNNING이 남으면 중단된 부분 실행이다. CLI 검증 오류는 exit2이며 부족한 자료를 정상 점수로 대신하지 않는다. Python 라이브러리의 예상 밖 오류는 traceback/비정상 종료로 드러나며 완료로 기록되지 않는다.
