# 재현 가능한 특징과 분할

모든 모델 입력은 float64다. 순서는 각 adapter의 `NAMES`와 run manifest가 고정한다. 원시 ID·URL·IP 크기는 수치 특징에 넣지 않는다. 모든 log 변환은 자연로그 `log1p`다.

| Source/version | 관측 단위 | 계산과 단위 | 결측·경계 처리 |
|---|---|---|---|
| online-shop / public-http-5min-v1 | 가명 client+UA × UTC 5분 | 요청 수, unique path 수, `1-unique_paths/count`, 응답 body bytes 합/평균/최대, 4xx/5xx 비율, unique method 수, 정렬된 요청 간격 평균(초)과 CV | 수량·bytes·간격평균은 log1p. CV=표준편차/평균, 모든 간격 0이면 실제 CV 정의를 0으로 고정. bytes `-` 거부. capture 시작/끝 window·요청 2개 미만 제외 |
| rbd24 / rbd-phishing-allowlist-v1 | 게시된 phishing desktop user/entity/time 행 | DNS/SSL/HTTP interlog q1..q5와 mean, GET/POST/HEAD 및 status200/400 ratio: adapter 23개 allowlist | 단위·window width 미검증이므로 원자료 수치 의미로만 사용. 모든 SMTP·compromised 지표 등 제외. finite 검사, 충돌 격리. service bytes로 해석하지 않음 |
| rba / synthetic-login-causal-v1 | 합성 로그인 시도 | 과거 시도 수(log), 첫 관측 0/1, 이전 관측 이후 초(log), country/IP/device/browser 각각 신규성 0/1·동일 값 과거 횟수/전체 과거 횟수 | 첫 관측에는 elapsed=0과 first=1을 함께 사용(결측을 정상으로 대체하지 않음). 필수 맥락 빈 값 제외. 같은 시각의 모든 특징 산출 후 이력 갱신 |

가명키는 `SHA256(JSON([source,*parts], ensure_ascii=True))`로 namespace를 분리한다. 비밀 HMAC이나 재식별 방지 보장을 뜻하지 않는다. 공개 가명 식별자는 원자료 밖으로 출력하지 않는다.

unique timestamp의 60/80% 경계를 정하고 train/calibration/test를 나눈다. **행 수가 정확히 60/20/20이라는 뜻은 아니다.** 다음 partition 시작을 HTTP 300초, RBD24 86400초, RBA 3600초 지연한다. 같은 timestamp는 분리하지 않는다. RBD의 원 window 길이가 미확정이므로 embargo만으로 겹침이 없음을 입증하지 않는다. HTTP는 session ID가 없어 window보다 긴 세션 중복은 미검증이다.

Scaler·중앙값·IQR은 train으로만 fit한다. IF/LOF/통계 baseline은 같은 후보 reference를 사용한다. label0가 없는 unlabeled source는 오염 가능성이 있는 전체 train으로 실험한다. label이 있는 source는 label0만 reference로 사용하고 -1은 학습·정답 지표에서 제외한다. 지도학습은 train의 0/1을 사용하며 두 클래스가 없으면 생략한다.

seed=42, train 최대 10,000행. train 안에서만 표본을 고른다. test를 보고 알고리즘 설정·임계값을 최적화하지 않는다. calibration reference의 99% quantile(method=higher)을 임계값으로 정하고 `score > threshold`를 사용한다. calibration 1%는 실제 test/운영 FPR 보장이 아니다.

manifest의 source SHA256·feature 순서/hash·code SHA256·split index SHA256·package lock·seed로 재현 조건을 추적한다. run의 `source_snapshot/`은 실행 당시 Python 소스다. 시간과 직렬화 파일 바이트는 플랫폼에 따라 달라질 수 있다.
