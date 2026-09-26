# 이전 Redis 실험 실행 안내 — 대체됨

사용자의 최신 지시로 Redis를 제거했다. 현재 명령은 [10 파일 pipeline 실행 안내](../10-file-pipeline/RUNBOOK.md)를 따른다. 08의 [결과](RESULTS.md)는 당시 실행한 Redis 검증의 역사 기록이며 현재 Redis가 필요하거나 실행 중이라는 뜻이 아니다.

준비된 feature JSONL을 읽는 `python -m zetty_uba.lab run-file`도 유지하지만 실제 로그→피처→탐지는 `python -m zetty_uba.lab.http_file`을 사용한다.
