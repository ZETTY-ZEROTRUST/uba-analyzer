# ZETTY 연결과 Git 작업 STAR 기록

## S — 상황

기존 uba-analyzer에는 사용자 미커밋 변경과 실험이 있고, 새 C-02 이벤트 schema/fixture와 backend producer는 아직 없다. 현재 GitHub 계정 jjyj0203의 원본 저장소 권한은 READ다.

## T — 구현 의도

develop에서 분기한 독립 작업공간으로 공개 데이터 학습 코드를 연결하고 커밋/PR로 검토 가능하게 만든다. 모델 입력 의미가 다른데 기존 운영 pipeline에 연결해 정상 작동한다고 보고하지 않는다.

## A — 실제 작업과 문제 개선

- 원본 develop `a192b81bf29a8372cfe081751c45c25268a1820b`에서 `feature/public-data-training-star` 분기. 사용자 기존 checkout의 변경은 보존했다.
- 신규 `src/zetty_uba` CLI는 source parser→feature→time split→fit→calibrate→test→artifact 순서로 연결된다.
- 원본 push/merge 권한이 없어 같은 계정의 `jjyj0203/uba-analyzer` 포크를 생성했다.
- macOS Git credential과 gh 계정이 달라 최초 push가 거부됐다. 격리 checkout의 GitHub credential helper만 gh로 지정한 뒤 OAuth `workflow` scope가 없다는 정확한 오류를 확인했다.
- workflow 변경 권한은 확대하지 않았다. 새 테스트 workflow는 `ml-tests.workflow-example.txt`라는 비활성 문서로 옮겼다. **CI가 구성/통과됐다고 보고하지 않는다.** 동일 테스트는 로컬에서 실행했다. 기존 main 배포 workflow는 변경하지 않았다.

## 서비스 연결에 필요한 다음 단계

1. log-pipeline owner가 C-02 schema/fixture와 revision/hash를 고정한다.
2. 검증된 actor 기반 서비스 관측과 공개 client+UA/합성 user의 차이, route/bytes/window 품질을 비교한다. RBD DNS/SSL 특징은 서비스 HTTP 특징으로 대체해 같은 모델을 로드할 수 없다.
3. 서비스 자료로 특징 일치 검사·train/calibration/test를 별도로 만들고 다시 학습한다. 모델/feature/threshold/source/hash 불일치는 미평가로 처리한다.
4. fake adapter와 schema round trip을 검증하고 Compose에서 관찰/dry-run으로 실행한다.
5. 승인된 로컬 모의 계정에서만 policy→Auth/BFF command·TTL·멱등성·조치/해제·실패 복구를 검증한다.

## R — 현재 도달 범위

공개 자료 offline 학습 코드 연결과 학습 artifact 생성은 수행했다. 실제 Redis/ES consumer, Auth/BFF 집행, 계정 잠금, 외부 알림, 서비스 배포는 미실행이다. PR URL·merge 여부·최종 보관 위치는 실제 확인 후 아래 기록에 추가한다.

### 원격 진행

비활성 workflow 예제로 변경한 후 기능 브랜치 push가 성공했다. [원본 develop 대상 PR #4](https://github.com/ZETTY-ZEROTRUST/uba-analyzer/pull/4)를 생성했다. GitHub는 base=develop, mergeable=true를 반환했다. 충돌 없음은 계정의 merge 권한이 있다는 뜻이 아니다.

### 최종 로컬 보관 확인

- 작업 checkout: `/Users/jjyj2302/zetty/uba-training`, branch `feature/public-data-training-star`.
- 공용 Python venv: `/Users/jjyj2302/zetty/.venv`.
- 검증된 공개 원자료 세 파일: `/Users/jjyj2302/zetty/ml-data/20260926/`.
- 완료 run 세 개: `/Users/jjyj2302/zetty/ml-runs/20260926/{online-shop-final,rbd24-final,rba-final}/`.
- copy 전 원자료 공식 MD5와 크기, copy 후 각 파일 SHA256 일치를 확인했다. 기존 파일이 다르면 덮어쓰지 않는 복사 절차를 사용했다.

원본 `/Users/jjyj2302/zetty/uba-analyzer`의 사용자 작업과 별도 checkout이다. 새 결과를 확인할 때는 위 `uba-training/docs/ml/README.md`를 연다. 원자료·모델은 Git 밖에 있고 각 run에 manifest·split indices·model artifact·실행 소스 snapshot이 있다.
