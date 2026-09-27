# 학습 STAR 결과

## S/T — 실험 범위와 이유

공개 자료별 관측 단위와 라벨을 분리한 CPU 모델 비교다. 초기 비용을 측정하고 실제 서비스 연결 전에 탐지 성능의 한계를 확인한다.

## A — 실제 실행

Python3.12.13/arm64, 고정 의존성, thread2, seed42, train 최대10,000개. 실행 명령은 [RUNBOOK](RUNBOOK.md)에 있다. 공식 checksum 확인부터 전처리·학습·보정·test·artifact 저장까지 측정했다. 다운로드/설치 시간은 제외된다.

## R — 측정 결과

| 자료/추출 범위 | 관측 수 | train/calibration/test | 전체 소요(초) | 프로세스 peak RSS(MiB) |
|---|---:|---|---:|---:|
| online-shop-final | 15,463 | 6,729/4,243/4,327 | 4.136 | 167.03 |
| rbd24-final | 16,676 | 10,266/2,552/2,144 | 1.699 | 179.33 |
| rba-final | 249,986 | 149,993/45,648/48,541 | 10.019 | 515.50 |

split의 train은 전체 train partition이며 모델별 실제 fit 행 수·reference 표본 수는 manifest에서 확인한다. 고정 CPU 제한과 작은 표본 실험이므로 전체 RBA 3천만 건 이상이나 실서비스 비용으로 외삽하지 않는다.

HTTP/RBD24는 source snapshot 및 라벨 경계 보완 후 재실행했다. 초기 실행과 각 모델 threshold·test metrics가 정확히 일치했다. artifact 바이트나 실행 시간을 동일하다고 주장하지 않는다.

실제로 오래 걸린 것은 학습보다 RBA 원본 다운로드였다. 긴 연결이 두 번 끊겼고 자동 retry가 처음 resume 위치부터 재전송했다. 해당 프로세스를 종료하고 HTTP206/content-range 지원을 확인한 뒤 32MiB 구간·동시 요청4개로 바꿨다. 각 조각 크기와 결합 원본의 공식 size/MD5를 검증한 뒤에만 학습한다.
