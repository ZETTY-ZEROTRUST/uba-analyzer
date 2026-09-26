# 데이터 audit 실행 기록

## S/T — 출처와 조건

공개 자료 4종의 metadata를 조회했다. 원본은 Git 밖에 저장한다.

## A — 실제 문제와 개선

- Online Shop: 28,630,570 bytes 확보. 공식 MD5 `725822e13e09281b498e7cd5d082a039` 일치.
- EClog: API HTTP 400. `required Guestbook response for guestbookID 356`가 원인이다. 임의 신원으로 제출하거나 다른 저장 경로로 우회하지 않는다. metadata audit만 완료하고 데이터 확보/학습은 보류한다.
- RBD24: Phishing desktop 단일 task 12,559,333 bytes 확보, MD5 `c55ef9d902973ab50b21399f5e50fabe` 일치. 16,936행·schema를 확인했고 충돌 전처리 및 학습 결과를 후속 단계에 기록했다. 다른 task 전체를 학습하지 않았다.
- RBA: ZIP 1,093,700,330 bytes 확보, 공식 MD5 `cc1b1078b3929650e6c08678caffcc57` 일치. 긴 연결 중단을 구간 다운로드로 개선했다. 12개 ZIP member 중 CSV는 하나(9,052,907,531 bytes)이며 디스크로 추출하지 않고 prefix 250,000행만 읽는다. 전체 행을 학습했다고 표현하지 않는다.

## R — 현재 상태

EClog 다운로드는 사용자 Guestbook 응답이 필요하다. 다른 자료 학습은 이 조건에 의존하지 않는다. 전체 학습 결과는 후속 기록으로 추가한다.

세 Zenodo 자료의 제목·제작자·DOI·배포일·라이선스·파일 checksum은 [sources.json](sources.json)에 보존했다. 공식 배포물에서 특징/표본을 파생했고 재배포된 원자료는 이 Git 저장소에 포함하지 않는다. RBA 인용: Wiefling, Jørgensen, Thunem, Lo Iacono (2022), *Pump Up Password Security! Evaluating and Enhancing Risk-Based Authentication on a Real-World Large-Scale Online Service*, DOI [10.1145/3546069](https://doi.org/10.1145/3546069). [제작자 안내](https://github.com/das-group/rba-dataset)의 합성 자료·운영 IDS 사용 제한을 따른다.
