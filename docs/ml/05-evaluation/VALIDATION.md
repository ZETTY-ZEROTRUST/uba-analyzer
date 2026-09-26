# 실행한 검증

ZETTY `.venv`에서 `PYTHONPATH=src OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 python -m unittest discover -s tests/ml -q`: **15개 통과**.

- 시간 그룹 분리·embargo, 미지 라벨 FPR=null, 임계값 tie와 NaN 거부
- HTTP bytes 누락/0 구분·입력 길이·capture boundary·초 단위 반복 보존
- source checksum 실패 거부
- 실제 네 estimator의 학습/평가/artifact 출력, 기존 output 덮어쓰기 거부
- RBD 충돌 전체 제외와 완전 중복 제거
- RBA tied timestamp·과거 이력·outcome/미래정보 독립, 역순 시각 거부, prefix cutoff
- RBA 필수 맥락 누락·ZIP 경로·긴 입력 제한
- unknown-only 라벨 task가 정상 reference로 바뀌지 않는지 확인

HTTP/RBD24 실제 파일로 재실행했으며 초기/최종 run의 모델별 threshold와 test 지표가 일치했다. Git 변경의 공백 검사는 `git diff --check`로 확인한다. CI는 workflow scope 제한으로 비활성 예제만 제공하며 원격 CI 통과를 주장하지 않는다.

미검증 범위: 운영 데이터, C-02 schema round trip, Redis/ES/Auth/BFF 연결, incident 단위 지표, public→service domain shift, 전체 RBA 기간, EClog 학습. 공개 자료의 artifact를 운영에 배포하지 않았다.

RBA 전체 ZIP 1,093,700,330 bytes와 공식 MD5 검증 후 prefix 250,000행으로 네 모델을 실행했고 `status=COMPLETED`를 확인했다. 분석 가능한 관측 249,986개이며 test ATO 1건이라는 분모 한계를 보고했다. 원자료 ZIP 안의 9GB CSV 전체 추출/학습은 하지 않았다.
