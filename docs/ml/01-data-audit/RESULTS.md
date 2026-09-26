# 데이터 audit 실행 기록

## S/T — 출처와 조건

공개 자료 4종의 metadata를 조회했다. 원본은 Git 밖에 저장한다.

## A — 실제 문제와 개선

- Online Shop: 28,630,570 bytes 확보. 공식 MD5 `725822e13e09281b498e7cd5d082a039` 일치.
- EClog: API HTTP 400. `required Guestbook response for guestbookID 356`가 원인이다. 임의 신원으로 제출하거나 다른 저장 경로로 우회하지 않는다. metadata audit만 완료하고 데이터 확보/학습은 보류한다.
- RBD24: Phishing desktop 단일 task 파일 확보·schema 검사 예정. 나머지 task 전체를 학습했다고 표현하지 않는다.
- RBA: ZIP 다운로드 진행. 완전한 다운로드와 checksum 확인 후에만 bounded CSV 스트림을 읽는다.

## R — 현재 상태

EClog 다운로드는 사용자 Guestbook 응답이 필요하다. 다른 자료 학습은 이 조건에 의존하지 않는다. 전체 학습 결과는 후속 기록으로 추가한다.
