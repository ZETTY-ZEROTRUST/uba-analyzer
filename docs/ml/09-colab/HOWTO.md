# 현재 학습 결과 확인부터 Colab 재개까지

## 현재 어디까지 완료됐나

- Online Shop 11개 + RBD24 12파일×14개 = **179개 모델 최종 평가 완료**.
- RBA 원본 **31,269,264행** 전부 확인, 유효 **31,267,738행** 준비 완료. **11개 모델의 학습·보정·validation 완료**.
- 마지막 Random Forest fit에서 사용자 요청으로 중단. RBA 전체 후보의 최종 test와 모델 선택은 아직 없다.
- EClog는 제공자 필수 Guestbook 정보가 없어 받지 못했다.

[전체 비교표 CSV](../07-full-data-study/comparison.csv)를 Excel 또는 편집기로 연다. `test_recall`은 실제 공격 중 탐지 비율, `test_precision`은 탐지 중 정답 비율, `test_fpr`은 정상 중 잘못 탐지한 비율이다. None/빈칸은 0점이 아니라 미평가·분모 없음이다. Online Shop에는 정답이 없어 FPR/recall을 산출하지 않았다.

```bash
cd /Users/jjyj2302/zetty/uba-training
/Users/jjyj2302/zetty/.venv/bin/python scripts/ml/inspect_study.py \
  /Users/jjyj2302/zetty/ml-runs/20260927-full/runs
```

JSON만 읽는 명령이며 모델 fit을 실행하지 않는다. 선택 모델은 validation으로 정했고 최종 test로 다시 고르지 않는다. task별 모델/피처가 달라 source 간 단일 순위로 비교하지 않는다.

## Colab 재개 순서

1. [Colab 노트북 열기](https://colab.research.google.com/github/jjyj0203/uba-analyzer/blob/feature/public-data-training-star/notebooks/zetty_rba_colab.ipynb). Google 계정으로 로그인하고 Drive에 사본을 저장한다.
2. **Google 호스팅 runtime**을 연결한다. `로컬 런타임 연결`은 사용하지 않는다. CPU 모델이므로 GPU 할당은 필수가 아니다. Python 3.12/3.13 여부를 첫 셀이 검사한다. RAM이 부족한 runtime이면 메모리가 더 큰 runtime을 선택하거나 새 runtime에서 진행해야 한다. 무료/유료 자원 가용성을 보장하지 않는다.
3. Mac의 `/Users/jjyj2302/zetty/ml-runs/20260927-full`에서 아래 두 디렉터리를 Drive `내 드라이브/zetty/20260927-full`에 같은 구조로 업로드한다. Mac에서는 업로드만 하며 학습하지 않는다.

```text
MyDrive/zetty/20260927-full/
  prepared/rba/
    dataset.json
    x.bin
    times.bin
    entities.bin
    labels.bin
  runs/rba/
    study.json
    split_indices.npz
    *.joblib
    source_snapshot/...
    progress.json
```

4. 노트북 1~4번을 실행한다. Python/패키지 설치, Drive 연결, 업로드 경로와 저장 모델 목록을 확인한다. 기본값 fresh를 `MODE = 'resume'`으로 변경한다. 기존 Mac checkpoint는 Python 3.12에서만 재개한다. 배열만 약 2.66GB이며 모델/분할 파일이 추가된다. SQLite 이력 cache와 원본 ZIP은 resume에 필요하지 않다.
5. 5번 셀에서 실행한다. 저장된 11개 모델은 재사용하고 중단된 RF는 처음부터 fit한다. 그 뒤 validation으로 선택을 고정하고 12개 후보의 전체 test를 평가한다. exact LOF 두 후보는 원래 계획의 계산 한도로 생략한다. RAM/CPU가 달라 Mac 기준 남은 시간을 Colab에 그대로 적용하지 않는다.
6. 6번 셀에서 `COMPLETED`, selection, 모든 후보 지표를 확인한다. **RBA final test는 이때 처음 생성된다.** VM이 끊겼으면 `colab-runs/<실행ID>` 백업 디렉터리를 CHECKPOINT로 바꿔 새 실행에서 이어간다. 부분 fit은 다시 수행될 수 있다.
7. 7번 셀에서 결과 ZIP을 내려받는다. Mac의 새 run 디렉터리에 보관한다. RBA 결과는 RBA 피처 replay에서 사용해야 하며, [현재 HTTP 파일 pipeline](../10-file-pipeline/RUNBOOK.md)에 넣으면 feature/source 불일치로 거부된다. 공개 RBA 피처 replay는 `zetty_uba.lab run-file`에 해당 모델과 manifest hash를 지정한다.
8. 작업 후 Colab의 runtime 연결을 해제/삭제한다. 결과는 Drive backup에 남는다.

## 업로드를 피하려면

`MODE = 'fresh'`로 바꾸면 Colab에서 공식 RBA ZIP을 직접 받아 전처리부터 실행한다. 기존 RBA 11개 후보도 다시 학습하는 별도 버전이다. 완료된 Online Shop/RBD는 재학습하지 않는다. 원본 size/MD5와 CSV EOF/CRC를 확인한다.

## 현재 제공한 것과 실제 실행 여부

노트북, 코드, checkpoint, 로컬 추론 환경을 준비했다. Google 계정 로그인·Drive 승인·업로드·Colab 실제 학습은 아직 수행하지 않았다. 준비됐다는 것과 원격 학습이 완료됐다는 것을 구분한다. Colab 자원/VM 수명은 [공식 FAQ](https://research.google.com/colaboratory/faq.html)를 따른다.

Python 3.13에서는 기본값 `MODE = 'fresh'`로 새 RBA 학습을 실행한다. 3.12 checkpoint를 3.13에서 재개하지 않는다. 기존 Colab 사본은 자동 갱신되지 않으므로 최신 노트북을 다시 열고 새 런타임에서 시작한다. [수정 과정](PYTHON313.md).
