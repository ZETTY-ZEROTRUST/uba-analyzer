"""
UBA 분석기 메인 - 5분 배치 (Layer 1 + Layer 2)

흐름:
  1. log_fetcher: ES에서 최근 6분 로그
  2. rule_engine: Layer 1 (T-rules) 매칭
  3. alert_saver: 룰 엔진 알림 ES 저장
  4. llm_analyzer: Layer 2 (LLM) 회색지대 분석
  5. alert_saver: LLM 알림 ES 저장
  6. 5분 sleep 후 반복

실행:
  python3 main.py              # 무한 반복
  python3 main.py --once       # 1회 실행 후 종료
"""
import sys
import time
import argparse
import logging
from datetime import datetime, UTC

from log_fetcher import get_es_client, fetch_recent_logs
from rule_engine import analyze_logs
from alert_saver import save_alerts, save_llm_alerts
from llm_analyzer import analyze_with_llm, get_anthropic_client


# === 설정 ===
BATCH_INTERVAL_SECONDS = 300  # 5분
FETCH_WINDOW_MINUTES = 6      # 5분 + 1분 여유


# === 로깅 ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# elasticsearch + httpx 로그 수준 낮추기 (시끄러움)
logging.getLogger("elasticsearch").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("anthropic").setLevel(logging.WARNING)
logger = logging.getLogger("uba-analyzer")


def run_batch(es, anthropic_client=None):
    """1회 배치 실행"""
    batch_start = time.time()
    
    logger.info(f"=== 배치 시작 (윈도우: 최근 {FETCH_WINDOW_MINUTES}분) ===")
    
    # 1. 로그 수집
    try:
        logs = fetch_recent_logs(es, minutes=FETCH_WINDOW_MINUTES)
        logger.info(f"  로그 수집: {len(logs)}건")
    except Exception as e:
        logger.error(f"  로그 수집 실패: {e}")
        return
    
    if not logs:
        logger.info("  분석할 로그 없음")
        return
    
    # 2. Layer 1: 룰 엔진
    try:
        rule_result = analyze_logs(logs)
        summary = rule_result['summary']
        logger.info(f"  [L1] 룰 매칭: {summary['rule_matched']}건")
        logger.info(f"  [L1] 전체 패턴: {summary['global_alerts_count']}건")
        logger.info(f"  [L1] LLM 대상: {summary['passed_to_llm_count']}건")
    except Exception as e:
        logger.error(f"  룰 엔진 실패: {e}")
        return
    
    # 3. 룰 엔진 알림 저장
    if summary['rule_matched'] > 0 or summary['global_alerts_count'] > 0:
        try:
            save_result = save_alerts(rule_result, es)
            logger.info(f"  [L1] ES 저장: {save_result['saved']}건 → {save_result['index']}")
        except Exception as e:
            logger.error(f"  [L1] 저장 실패: {e}")
    
    # 4. Layer 2: LLM 분석
    if anthropic_client and rule_result.get('passed_to_llm'):
        try:
            llm_alerts = analyze_with_llm(rule_result['passed_to_llm'], anthropic_client)
            logger.info(f"  [L2] LLM 알림: {len(llm_alerts)}건")
            
            # 5. LLM 알림 저장
            if llm_alerts:
                save_result = save_llm_alerts(llm_alerts, es)
                logger.info(f"  [L2] ES 저장: {save_result['saved']}건 → {save_result['index']}")
        except Exception as e:
            logger.error(f"  [L2] LLM 분석 실패: {e}")
    
    elapsed = time.time() - batch_start
    logger.info(f"=== 배치 완료 ({elapsed:.2f}초) ===\n")


def run_loop(es, anthropic_client):
    """무한 반복 모드"""
    logger.info(f"UBA 분석기 시작 (주기: {BATCH_INTERVAL_SECONDS}초)")
    logger.info(f"Layer 1 (룰 엔진) + Layer 2 (LLM) 활성화")
    logger.info(f"중지: Ctrl+C")
    logger.info("")
    
    while True:
        try:
            run_batch(es, anthropic_client)
        except KeyboardInterrupt:
            logger.info("사용자 중지")
            break
        except Exception as e:
            logger.error(f"배치 오류: {e}")
        
        # 다음 배치 시각
        next_run = datetime.now(UTC).timestamp() + BATCH_INTERVAL_SECONDS
        next_run_str = datetime.fromtimestamp(next_run, UTC).strftime("%H:%M:%S UTC")
        logger.info(f"다음 배치: {next_run_str} ({BATCH_INTERVAL_SECONDS}초 후)\n")
        
        try:
            time.sleep(BATCH_INTERVAL_SECONDS)
        except KeyboardInterrupt:
            logger.info("사용자 중지")
            break


def main():
    parser = argparse.ArgumentParser(description="UBA 분석기 (Layer 1 + Layer 2)")
    parser.add_argument("--once", action="store_true", help="1회 실행 후 종료")
    parser.add_argument("--no-llm", action="store_true", help="LLM 비활성화 (룰 엔진만)")
    args = parser.parse_args()
    
    # ES 연결
    try:
        es = get_es_client()
        info = es.info()
        logger.info(f"ES 연결 OK ({info['version']['number']}, {info['cluster_name']})")
    except Exception as e:
        logger.error(f"ES 연결 실패: {e}")
        sys.exit(1)
    
    # Anthropic 클라이언트 (선택)
    anthropic_client = None
    if not args.no_llm:
        try:
            anthropic_client = get_anthropic_client()
            logger.info(f"Anthropic LLM 클라이언트 OK")
        except Exception as e:
            logger.warning(f"LLM 비활성화: {e}")
    
    if args.once:
        logger.info("--once 모드: 1회 실행")
        run_batch(es, anthropic_client)
    else:
        run_loop(es, anthropic_client)


if __name__ == "__main__":
    main()
