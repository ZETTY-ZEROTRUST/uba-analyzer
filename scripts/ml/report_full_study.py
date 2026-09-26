"""Summarize completed independent studies without selecting by final test."""
import argparse
import csv
import json
from pathlib import Path
import shutil


def report(root, output):
    studies = []
    for path in sorted((root / 'runs').glob('*/study.json')):
        data = json.loads(path.read_text())
        if path.parent.name == 'Phishing_smartphone' and data['status'] == 'FAILED':
            continue
        if data['status'] != 'COMPLETED':
            raise ValueError(f'incomplete study: {path.parent.name}')
        studies.append((path.parent.name, data))
    if len(studies) != 14:
        raise ValueError('expected 14 completed source studies')
    output.mkdir(parents=True, exist_ok=True)
    (output / 'manifests').mkdir(exist_ok=True)
    rows = []
    summaries = []
    for name, data in studies:
        (output / 'manifests' / f'{name}.json').write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n')
        selected = data['selection']['selected_model']
        for model, result in data['models'].items():
            row = {'source': name, 'model': model, 'status': result['status'], 'selected_by_validation': model == selected}
            for phase in ('validation', 'test'):
                for metric in ('rows', 'labeled_rows', 'precision', 'recall', 'fpr', 'flag_rate', 'average_precision', 'roc_auc'):
                    row[f'{phase}_{metric}'] = result.get(phase, {}).get(metric)
                for key in ('tp','fp','fn','tn'):
                    row[f'{phase}_{key}'] = (result.get(phase, {}).get('confusion') or {}).get(key)
            row.update({key: result.get(key) for key in ('fit_rows','fit_seconds','calibration_seconds','validation_seconds','test_seconds','test_ms_per_row','reason')})
            rows.append(row)
        value = data['models'][selected]['test'] if selected else {}
        summaries.append({'source': name, 'rows': data['dataset']['rows'], 'selected': selected,
                          'test': value, 'seconds': data['last_process_seconds'], 'peak_rss_mib': data['process_peak_rss_mib']})
    with (output / 'comparison.csv').open('w') as file:
        writer=csv.DictWriter(file, fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    shutil.copy2(root/'rbd-overlap.json',output/'rbd-overlap.json')
    evaluated=sum(row['status']=='EVALUATED' for row in rows)
    skipped=sum(row['status']=='SKIPPED' for row in rows)
    summary={'status':'COMPLETED_AVAILABLE_SOURCES','source_studies':len(studies),'evaluated_models':evaluated,
             'skipped_models':skipped,'blocked_sources':{'eclog':'provider requires guestbook name/email/institution/position; not supplied'},
             'recovered_runs':{'Phishing_smartphone':'Phishing_smartphone-expanded'},'sources':summaries}
    (output/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
    def pct(value):return '—' if value is None else f'{100*value:.3f}%'
    lines=['# 전체 자료 학습·비교 결과 — STAR', '',
           '## S / T', '', '부분 자료로는 전체 기간과 모델 차이를 판단하기 어려워 14개 source/task를 분리하고 최대 14개 후보를 비교했다. 실행 전 계획과 변경 이유는 README 및 ISSUES에 기록했다.', '',
           '## A — 실제 수행', '',
           'RBA CSV 31,269,264행을 EOF/ZIP CRC까지 검사하고 1,526개 결측 행을 제외한 31,267,738개를 준비했다. 전처리는 1,243.448초였다. 전체 처리 후 시간순 train/calibration/validation/test와 unknown label 제외를 적용했다. RBD는 12개 원본을 각각 공식 MD5/크기로 확인했다.', '',
           'validation에서 recall 우선·FPR≤2%로 선택한 뒤 test를 한 번 평가했다. 아래 모델은 최종 test로 다시 고른 모델이 아니다. Online Shop은 정답 label이 없어 탐지 성능 우승자를 선정하지 않았다.', '',
           '## R — 완료와 비교', '', f'접근 가능한 자료 14개 연구, 모델 {evaluated}개 최종 평가 완료, 사전 조건으로 {skipped}개 생략. EClog는 필수 Guestbook 정보가 없어 미학습이다.', '',
           '| Source | 준비 행 | validation 선택 모델 | test recall | test precision | test FPR | 학습·평가 초 | peak RSS MiB |',
           '|---|---:|---|---:|---:|---:|---:|---:|']
    for s in summaries:
        v=s['test'];lines.append(f"| {s['source']} | {s['rows']:,} | {s['selected'] or '정답 없음'} | {pct(v.get('recall'))} | {pct(v.get('precision'))} | {pct(v.get('fpr'))} | {s['seconds']:.1f} | {s['peak_rss_mib']:.1f} |")
    lines += ['', '## 해석·한계', '',
              '- 전체 후보별 confusion matrix·AP·ROC-AUC·소요 시간은 [comparison.csv](comparison.csv), Wilson95·seen/unseen·설정·hash·실제 fit 행은 manifests에 있다.',
              '- RBD 12개 파일 사이 20개 파일 쌍에 동일 user/entity/time이 있으며 전체 고유 조합은 576,800개다. task별 지표를 합쳐 독립 표본 성능으로 계산하지 않았다.',
              '- 희소 공격과 낮은 precision/recall을 숨기지 않는다. 선택 모델은 해당 validation 규칙의 결과이며 모든 공격에 가장 좋은 모델이라는 뜻이 아니다. RBA validation ATO는 6개여서 선택 근거가 특히 제한적이다.',
              '- HTTP label은 없으므로 flag rate를 오탐률로 부르지 않는다. RBA는 합성 로그인 연구이고 RBD는 task별 행동 실험이다.',
              '- RBA exact LOF 두 후보는 reference train 25만 초과의 계산 한도로 생략했다. HTTP 지도학습 세 후보는 label 부재로 생략했다.',
              '- Phishing smartphone 최초 보정 reference 95개 문제를 40/25/15/20 분할로 수정해 3,156개를 확보했다. validation/test 경계는 그대로이며 실패 기록을 보존했다.',
              '- v1과 v2는 자료 범위·분할·기준선이 달라 수치를 같은 조건의 성능 개선으로 비교하지 않는다.',
              '- peak RSS는 각 학습 프로세스의 최대 메모리이며 노트북 전체 메모리·온도·누적 디스크 쓰기를 의미하지 않는다.', '',
              '실행·재현 명령: [RUNBOOK](RUNBOOK.md). 공개 원본·mmap·모델 artifact는 Git 밖에 보관하고 코드·집계·manifest만 커밋한다.']
    (output/'RESULTS.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='sources'}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();report(args.root,args.output)
