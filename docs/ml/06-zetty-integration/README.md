# 학습 결과와 서비스 연결

다음 S/T/A는 2026-09-26 실행 전에 기록한 계획이다. 이후 수행 여부와 실제 문제·개선·검증은 [결과 기록](RESULTS.md)을 따른다.

## S — 상황

새 이벤트 schema/fixture(C-02)와 producer는 미완성이다. 공개 데이터의 관측 단위는 실제 인증 사용자와 다르다.

## T — 과제와 이유

학습·평가 artifact를 재현 가능하게 남기고 서비스 연결의 선행 조건을 명시한다.

## A — 실행 방법과 선택 이유

이번 단계는 offline training CLI와 보고서까지다. 새 모델을 구 score·등급 runtime에 연결하지 않는다. 후속 C-02 고정→service feature 적합성 검증→dry-run→로컬 모의 계정 대응 시험 순서다.

## 예상 문제와 개선 계획

모델·feature·threshold·source·code hash 불일치를 거부한다. 공개 benchmark 모델을 즉시 계정 잠금에 연결하지 않는다. 실서비스 통합·자동 조치는 미실행으로 기록한다.

## R — 결과

계획 작성 당시 미실행이었다. 이후 실제 실행과 미완료 범위를 [RESULTS](RESULTS.md)에 기록한다.
