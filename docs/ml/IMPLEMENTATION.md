# 신규 UBA 구현 안내 — 데이터·모델·대응 분리

> 2026-09-26 · offline 학습 CLI 구현 진행, 서비스 실행 구조는 미완료. 실제 결과는 [단계별 기록](README.md)을 따른다.
> [루트 지침](../../../AGENTS.md) → [인수인계](../../../docs/HANDOFF.md) → [전체 합의](../../../IMPLEMENTATION_AGREEMENT.md) → 이 문서 순서로 읽는다.

## 1. 범위와 현재 자산

입력·집계·학습·탐지·저장·사건·정책·알림·LLM adapter·테스트를 새로 구성한다. 7-factor 합산·수동 가중치·L0~L4, 기존 total_score/factor_breakdown/attacker_level을 신규 출력이나 fallback으로 유지하지 않는다.

현재 v1 경로는 `pipeline.py`, `ingest/`, `aggregate/`, `scoring/`, `storage/`, `user_profile.py`, `llm-agent/`, `scripts/`, 기존 ES/Kibana 자산이다. 현재 동작을 확인할 근거지만 새 요구사항은 아니다. 새 경로 완성 → consumer 전환 → 참조/동작 검사 → 구 코드 제거 순서다.

`experiments/isolation_forest/offline.py`는 미커밋 사용자 자산이다. 정상 train/calibration, 시간순 split, 누락 검사, seed·hash 기록은 검토할 가치가 있다. 기존 8-feature·threshold·scenario 목록·최소 표본 가드를 새 모든 모델에 자동 승계하지 않는다. 원본을 보존하고 필요한 아이디어를 새 테스트로 검증한다.

## 2. 데이터 소유와 정상 선별

### 자료별 역할

| source ID 제안 | 원자료·관측 단위 | 역할·준비 확인 |
|---|---|---|
| `online-shop-18895701` | [Online Shop Logs](https://zenodo.org/records/18895701), 쇼핑몰 HTTP 요청 | HTTP parser·초기 모델. label 유무·가명 IP/UA·URI/status/bytes 타입·결측 확인 |
| `eclog-z834ik` | [EClog](https://dataverse.harvard.edu/dataset.xhtml?persistentId=doi:10.7910/DVN/Z834IK), 장기 HTTP 요청 | 일중/장기 패턴. .NET ticks·timezone·수집 gap·봇 확인 |
| `rbd24-13787591` | [RBD24](https://zenodo.org/records/13787591), user/device window | 별도 행동 benchmark. task/device·label·중복·window/ratio·IDS feature 확인 |
| `rba-6782156` | [RBA Login Dataset](https://zenodo.org/records/6782156), 합성 로그인 시도 | 로그인 이력 모델. label 의미·시간순 이력·합성 위치/RTT·범주형 값 확인 |

공식 확인 근거는 [전체 합의 §6](../../../IMPLEMENTATION_AGREEMENT.md#6-학습-데이터와-활용)에 있다. 전체 원자료 확보·선별·학습은 미완료다. 원자료는 Git 밖의 명시한 data volume에 보관한다. manifest에는 dataset ID/version·URL·license/citation·원본 checksum·adapter version·추출 범위·제외 사유를 기록한다.

Zenodo 세 자료는 CC BY 4.0이다. EClog의 배포 조건·인용 안내는 해당 version metadata와 함께 보존한다. [EClog 공식 API](https://dataverse.harvard.edu/api/datasets/:persistentId/?persistentId=doi:10.7910/DVN/Z834IK), [RBA 제작자 설명](https://github.com/das-group/rba-dataset)

### 정상 선별 규칙

- 쇼핑몰/EClog는 정상 정답이 없는 자료다. 필터·표본 검토로 후보 정상을 만들고 오염 가능성을 남긴다. 전체 자료의 outlier 실험과 검토된 정상만의 novelty 학습을 구분한다. label 없는 집합의 flag 비율을 FPR로 부르지 않는다.
- RBD24는 해당 위험 task의 label 0을 후보 정상으로 삼고 -1은 제외한다. 파일 간 동일 user/entity/window와 상충 label을 검사한다. 특정 위험의 음성을 모든 위험의 부재로 해석하지 않는다. IDS·피싱/compromised 지표가 정답을 노출하는지 제거 실험을 한다.
- RBA의 known account takeover·attack-IP 표본은 정상 학습에서 제외하거나 별도 검토한다. 성공=정상, 실패=공격으로 만들지 않는다. outcome/attack label은 선별·평가용이며 현재 시도 예측 feature에 넣지 않는다.
- RBA는 실제 행동의 통계관계를 보존한 합성 자료다. 제작자의 운영 IDS 사용 경고를 기록하고 연구/PoC 성과로 한정한다. 인공 IP/위치에 GeoIP를 다시 적용하거나 실제 이동 속도로 해석하지 않는다.
- 자료별 label_source·label_confidence·review_reason을 보존한다. 기존 모델 점수나 rule 결과로 정답을 생성하지 않는다.
- 공개 IP/UA는 인증된 user/session이 아니다. 없는 JWT·객체 ID·bytes를 생성하거나 누락을 0으로 바꿔 서비스 계약에 맞추지 않는다.

## 3. 모델과 feature 계약

| detector | 표본·feature 후보 | 입증할 범위 |
|---|---|---|
| HTTP 행동 | source별 관측 주체×window; 간격·반복·URI/route 범위·bytes·status 비율 | 조회의 수치적 이상. 익명 접속 단위와 service actor 단위 차이를 별도 평가 |
| 로그인 맥락 | 로그인 시도; 과거 이력의 출처/기기 신규성·빈도·이전 로그인 이후 시간 | 새로운 로그인 맥락. token 사용 중 탈취·동시 사용까지 이 자료만으로 입증하지 않음 |
| RBD24 행동 | 원자료 device/user window의 정의가 확인된 지표 | task별 benchmark. DNS/SMTP 없는 서비스에 같은 artifact를 바로 배포하지 않음 |

초기 수치 모델로 Isolation Forest를 검토하되 단순한 통계 비교 기준과 같은 holdout에서 비교한다. 알고리즘은 source audit 후 선택한다. 가명 ID·IP·ASN 정수의 크기를 연속적 위험 feature로 쓰지 않는다. RBA RTT는 결과/위치에 따른 합성 특성을 고려해 포함/제외 실험을 분리한다.

feature manifest는 source ID, observation unit, schema/feature version, 정렬된 이름·dtype·단위·계산식, window/cutoff, 필수 입력·결측 정책, 분류/가명 key version을 포함한다. URI 정규화·bytes 관측 위치·분모가 바뀌면 version을 바꾼다. RBD ratio를 실제 body bytes로 바꾸지 않는다.

관측 후보는 민감 조회/응답량, 로그인·세션 출처 변화, 객체·계정 탐색이다. 초기 모델이 표현할 범위만 선택한다. user×5분 count로 국가 교차·동시 사용·장기 저속 유출을 모두 탐지한다고 약속하지 않는다. 정상 다운로드·집중 이용·NAT·VPN·멀티탭·refresh를 대조군에 포함한다.

## 4. 학습·보정·평가

1. 자료별 schema/label/시각/중복/결측/관측 단위를 audit하고 최소 표본으로 parser를 검증한다.
2. 정상 train → 이후 정상 calibration → 더 이후 독립 정상/이상 test를 정의한다. 후보 정상뿐인 자료의 결과는 정답 기반 지표와 구분한다.
3. 동일 capture/session/window·중복본이 split 양쪽에 들어가지 않게 한다. RBD 파일 간 중복도 포함한다. 기존 사용자 미래 예측과 신규 사용자 holdout은 별도로 평가한다.
4. 전처리·encoder·분포 통계는 train에서 fit한다. 이력 feature는 관측 이전 기록만 사용한다. 1h/24h lookback은 purge gap과 과거 이력 접근 범위를 함께 정한다.
5. 모델 선택은 개발용 시간순 fold, threshold는 calibration을 사용한다. 최종 test를 보고 튜닝했다면 새 holdout이 필요하다.
6. dataset/split/feature/model/threshold/code version, checksum, seed, Python/dependency lock, 학습·보정 범위를 artifact manifest에 남긴다.
7. 신뢰한 train job의 artifact만 checksum 확인 후 읽기 전용으로 로드한다. 임의 외부 pickle/joblib을 로드하지 않는다.

IF를 선택한다면 -score_samples 같은 방향과 비교 연산자 > 또는 >=를 명시하고 tie를 검증한다. 이상 점수는 공격 확률이 아니다. 목표 calibration FPR은 test/실서비스 FPR 보장이 아니다. 복제한 표본 수는 독립 검증 근거가 되지 않는다.

정답 있는 test는 confusion matrix·precision/recall/FPR와 분모·표본·cohort를 보고한다. 모든 자료는 flag 비율·품질 제외율·추론 지연·메모리·재현성을 기록한다. incident recall·첫 탐지 지연은 window flag rate와 별개다. 공개 자료와 local simulated HTTP 성과도 분리한다.

공식 자료: [이상 탐지](https://scikit-learn.org/stable/modules/outlier_detection.html), [Data leakage](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage), [IsolationForest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html), [Artifact 저장](https://scikit-learn.org/stable/model_persistence.html).

## 5. 인증 트랙과 주고받는 계약

원본은 [log-pipeline 계약 안내](../../../log-pipeline/docs/contracts.md)가 소유한다. schema 경로·enum·index 이름·command payload를 UBA에서 중복 확정하지 않는다. 같은 revision/hash의 golden fixture를 Java/Python에서 사용한다.

| 계약 | UBA 책임 | 상대 책임 |
|---|---|---|
| security-event/2.0 | 검증·dedupe·목적별 표본 | Auth/API의 검증된 actor/상태/권한, edge의 최종 HTTP 관측 |
| anomaly-detection/1 | 모델·feature·threshold version과 품질·근거 | 저장/대시보드/policy consumer의 동일 schema 해석 |
| response command | 별도 policy의 scope·TTL·근거·멱등 ID | Auth/BFF의 호출자 권한·현재 상태 확인, 집행 결과·감사 |

검증 실패 actor는 null이다. raw JWT·RT·cookie·password·과도한 업무/UA 원문은 저장하지 않는다. 목적별 가명 actor/session/token/IP/resource key와 key version·provenance를 사용한다.

API decision과 edge completion을 request_id로 join해 한 요청을 중복 세지 않는다. login/refresh는 별도 표본이다. BFF 내부 IP를 실제 client로 집계하지 않는다. window end+allowed lateness는 cutoff이며 완전성 증명이 아니다. correlation 누락·collector gap·capture 경계는 품질 상태로 보존한다. late 자료는 새 dataset/input version으로 재평가한다.

결과 품질 상태는 EVALUATED / INSUFFICIENT_DATA / INCOMPLETE_WINDOW / MODEL_UNAVAILABLE / FEATURE_MISMATCH다. 미평가 score/flag는 null이다. detector/target/window/model/threshold/input version으로 ID를 생성하고 사건 correlation도 version 관리한다.

## 6. response policy와 선택 LLM

- 모델은 이상 결과를 생산한다. 점수 구간만으로 계정 잠금을 직접 호출하지 않는다.
- policy는 품질·추가 증거·상태·환경·대상·TTL·중복을 검토해 관찰/제한/재인증/폐기/잠금 요청을 결정한다.
- 최초 구현은 기록·dry-run이다. 이후 로컬 모의 계정에서 조치·해제·실패 복구·정상 사용자 영향을 검증한다. 자동 대응은 범위에 포함되지만 운영 적용 완료는 아니다.
- UBA가 Auth DB나 session Redis를 직접 수정하지 않는다. 인증된 command 경계와 Auth/BFF 집행 권한을 사용한다.
- fresh authentication이 기존 SSO cookie로 자동 통과하지 않는지, 현재/전체 세션 회수와 잠금 DoS·해제가 검증되는지 확인한다.
- policy/command/receipt를 ID·version·근거·상태·시각으로 추적한다. 중복 요청은 중복 부작용을 만들지 않고, 만료·대상 불일치·권한 없는 command는 집행하지 않는다.
- 모델 장애는 탐지 불가·backlog로 노출한다. Auth/API 기본 통제는 계속하며 옛 factor fallback은 없다.
- LLM은 선택 설명 adapter다. 점수·threshold·policy·command를 생성/변경하지 않는다. timeout·grounding 실패·전송 실패를 탐지 실패와 구분한다. 외부 API 없이 core를 실행한다.

## 7. 구현 경로와 작업 소유

현재 `datasets/`, `training/`, `__main__.py`와 `tests/ml/`에 offline 공개 데이터 경로를 구현했다. 아래 전체 구조 중 detection/policy/adapters 및 서비스 consumer는 후속 제안 경로다. source별 adapter와 core를 분리하는 목적이며 불필요한 서버를 추가하지 않는다.

```text
src/zetty_uba/
  datasets/     source manifest·parser·선별·split
  features/     detector별 순수 변환·품질 검사
  training/     fit·calibrate·evaluate·artifact
  detection/    artifact 검증·inference·사건 연결
  policy/       response 결정·dry-run
  adapters/     Redis Streams·ES·Auth command·선택 LLM
  cli/          prepare-dataset/build-features/train/calibrate/evaluate/detect
tests/          계약·단위·fixture·선택 Compose 통합
```

| 작업 | 소유 범위 | 완료 조건 |
|---|---|---|
| M-01 | datasets·source manifest·audit report | 작은 표본/metadata에서 schema·label·조건·시각·정상 후보 확인, 원본 Git 제외 |
| M-02 | datasets·features·CLI·fixture/tests | 동일 변환, 잘못된 시각/누락/중복/미래 이력 거부, split 재현 |
| M-03 | training·artifact·evaluation | 모델별 train/calibration/test와 단순 비교 기준, version/feature 불일치 거부 |
| M-04 | detection·policy·adapters·worker/tests | 신규 결과/incident·dry-run, 멱등성·부분 실패·모델 장애·command 기한 검사 |
| I-01~04 | 공통 owner와 fixture·Compose 통합 | producer payload 일치, stream 재처리, public→local 의미 검증, 조치·해제·감사 |

공통 schema·index mapping·Compose 진입점은 각 owner와 조율한다. backend의 JWT·발급대장·refresh·집행 코드는 인증 트랙 소유다. 같은 mapping을 동시에 수정하지 않는다.

현재 offline CLI·입출력·exit code는 [실행 안내](04-model-training/RUNBOOK.md)에 기록했다. 현재 pipeline.py --dry-run은 ES 조회를 포함하는 v1 명령이므로 신규 offline smoke로 쓰지 않는다. 새 모듈 import만으로 env 파일·외부 연결·모델 다운로드가 발생하지 않게 한다.

## 8. 재처리·검증·인수인계

Outbox 원본·receipt를 복구 근거로 보존하며 Redis AOF만을 원본으로 삼지 않는다. ES는 event-time index와 결정론적 ID를 쓴다. 항목별 write 성공·receipt 후 ACK, 부분 실패는 재시도·격리 상태로 남긴다. pending 회수·poison event·backlog·보존/삭제 조건을 시험한다.

검증 순서는 순수 fixture → 계약/feature/split → 학습/artifact → fake adapter → 승인된 Compose 통합이다. 실제 전체 dataset 처리·학습·외부 LLM·Slack·집행 여부를 구분해 보고한다. venv·고정 dependency와 실행 명령·버전·결과를 기록한다.

v1의 baseline 재계산, processing-day index/auto-ID, bulk 부분 실패 무시, profile 반복 누적은 재발 방지 사례다. 구 코드를 먼저 고쳐 새 모델을 그 점수 체계에 붙이는 작업으로 바꾸지 않는다.

다음 작업자는 repo status·사용자 실험과 [실행 결과](README.md)를 확인하고 미완료 데이터 조건 및 C-02 서비스 선행 조건부터 이어간다. Git은 루트 지침과 사용자 지시를 따른다. 신규 평가 보고서는 source·모델·환경·표본·분모·실행 결과를 포함한다.
