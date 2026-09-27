# 전체 실험 실행·재현

모든 명령은 `uba-training` 저장소 디렉터리에서 ZETTY `.venv`로 실행한다. v1 결과는 덮어쓰지 않는다. raw data/model/feature/history DB는 Git 밖에 있다.

```bash
export PYTHONPATH=src
export OMP_NUM_THREADS=2
export OPENBLAS_NUM_THREADS=2
ZETTY_PY=/Users/jjyj2302/zetty/.venv/bin/python

# 전체 RBA: ZIP 전체 checksum 확인 → CSV EOF/CRC 확인 → causal feature mmap
"$ZETTY_PY" -m zetty_uba.study prepare --source rba \
  --input /Users/jjyj2302/zetty/ml-data/20260926/rba-dataset.zip \
  --output /private/tmp/zetty-full-20260927/prepared/rba

# source별 전체 eligible train 및 독립 holdout 비교
"$ZETTY_PY" -m zetty_uba.study train \
  --prepared /private/tmp/zetty-full-20260927/prepared/rba \
  --output /private/tmp/zetty-full-20260927/runs/rba

# 유일한 보정 표본 부족 예외: 40/25/15/20, test/validation 고정
"$ZETTY_PY" -m zetty_uba.study train \
  --prepared /private/tmp/zetty-full-20260927/prepared/Phishing_smartphone \
  --output /private/tmp/zetty-full-20260927/runs/Phishing_smartphone-expanded \
  --train-fraction .4
```

실제 14개 source 큐 실행은 `scripts/ml/full_study.py --root /private/tmp/zetty-full-20260927 --initial-data /Users/jjyj2302/zetty/ml-data/20260926`을 사용했다. `caffeinate -i`는 이 실행 동안만 macOS 유휴 절전을 막는다. stage별 완료를 기록하며 모델 작업은 순차 실행한다. 원본 12개 RBD 파일은 root/data/rbd24, 검증 metadata는 root/rbd-files.json에 있다. 다운로드는 32MiB HTTP 구간 4개 동시, 전체 결합 후 공식 size/MD5를 검증했다.

## 재개와 상태 해석

- prepared/dataset.json의 COMPLETED와 파일 checksum이 있어야 학습을 시작한다.
- study.json의 모델 VALIDATED는 train/calibration/validation까지 완료, EVALUATED는 test까지 완료다.
- selection.json을 최종 test보다 먼저 저장한다. 선택에 final test를 사용하지 않는다.
- 동일 데이터·code·후보 설정의 기존 실행만 재개하며 계획 hash가 다르면 새 run 디렉터리를 요구한다.
- 전체 전처리의 중간 profile은 SQLite에 저장하지만 **임의 중간 CSV 행부터의 자동 재개는 구현하지 않았다.** 실패한 전처리는 새 디렉터리에서 원본부터 재실행한다. 완료된 전처리와 완료된 모델 단계는 재사용한다.
- 본 비교 도중 보정 부족 상태 기록·분할 인자 지원을 수정했다. 각 run의 source_snapshot과 code hash가 실제 실행 버전이다. 기본 50/15/15/20 계산과 모델 설정은 그대로이며 smartphone 예외만 .4를 명시했다.

## 읽어야 할 결과

`study.json`: 전체 출처·처리 수·실제 fit 수·후보 parameters·seed·모델/feature/split hash·validation/test 지표·시간·peakRSS. `selection.json`: test 이전 선택. `*.joblib`: 이 실행에서 만든 모델과 scaler/mapper, 특징·source·계획 hash. **threshold는 study.json의 해당 모델 결과와 함께 사용해야 한다.** 서로 다른 source/version의 파일을 섞지 않는다. 새 서비스 runtime 연결은 별도 계약 작업이다.

원본 checksum을 검증한 전체 데이터를 처리했다는 뜻과 모델 학습에 모든 행을 넣었다는 뜻을 구분한다. 품질 제외·라벨 -1·시간 holdout을 그대로 유지한다. IF는 전체 train pool을 입력받아 tree별 subsample을 사용하고, SGD/KMeans는 모든 eligible train을 각 epoch 순회한다.

근거: 설치 버전 [SGDOneClassSVM](https://scikit-learn.org/1.7/modules/generated/sklearn.linear_model.SGDOneClassSVM.html), [MiniBatchKMeans](https://scikit-learn.org/1.7/modules/generated/sklearn.cluster.MiniBatchKMeans.html), [평가 지표](https://scikit-learn.org/1.7/modules/model_evaluation.html). EClog의 필수 Guestbook 응답 방식은 [Dataverse API](https://guides.dataverse.org/en/6.10/api/dataaccess.html)를 확인했다.
