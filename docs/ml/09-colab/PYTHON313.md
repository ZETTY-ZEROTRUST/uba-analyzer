# Colab Python 3.13 호환 수정 — STAR

## Situation
사용자가 Colab Python 3.13.15에서 첫 셀을 실행했으나 3.12 전용 assert에서 실패했다. 학습은 시작되지 않았다.

## Task
로컬 학습 차단을 유지하며 새 학습은 Python 3.12/3.13을 지원한다. 기존 checkpoint는 생성 당시 Python minor와 패키지가 같은 환경에서만 재개한다.

## Action (구현 전 계획)
노트북/실행기 버전 검사를 함께 변경하고 fresh를 기본값으로 설정한다. 고정 의존성의 cp313 Linux wheel을 확인한다. 재개 불일치는 복사/모델 로딩 전에 거부한다. 기존 clone은 덮어쓰지 않고 최신 코드 여부를 검사해 오래된 스크립트 실행을 차단한다.

## Result
- PyPI release JSON에서 numpy 2.2.6, scipy 1.15.3, scikit-learn 1.7.2, pyarrow 21.0.0의 CPython 3.13 manylinux x86_64 wheel 및 joblib 1.5.2/threadpoolctl 3.6.0의 공용 wheel 확인. 패키지 pin은 유지했다.
- checkpoint/runtime 테스트 7개 통과. 지원 버전·미지원 버전·로컬 차단·교차 minor 재개 차단·notebook 구문 및 첫 셀을 검사했다. 버전 검사는 mock으로 수행했으며 실제 3.13 실행 검증으로 간주하지 않는다.
- Colab 설치 셀에 새 subprocess에서 6개 패키지 import 검사 추가. 실제 Colab 설치/import/학습은 아직 미검증이다.
- 새 노트북 사본과 새 런타임에서 1번부터 실행해야 한다. 이전 사본의 첫 셀만 수정하면 옛 실행기가 그대로 남을 수 있다.

근거: [NumPy 2.2.6](https://numpy.org/doc/2.3/release/2.2.6-notes.html), [SciPy 배포](https://pypi.org/project/scipy/1.15.3/#files), [scikit-learn 배포](https://pypi.org/project/scikit-learn/1.7.2/#files), [PyArrow 배포](https://pypi.org/project/pyarrow/21.0.0/#files).
