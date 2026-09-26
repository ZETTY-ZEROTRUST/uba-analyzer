"""Inspect saved study metadata without loading or training a model."""
import argparse
import json
from pathlib import Path

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('path',type=Path);args=p.parse_args()
paths=[args.path/'study.json'] if (args.path/'study.json').is_file() else sorted(args.path.glob('*/study.json'))
if not paths:raise SystemExit('No study.json found; pass a run directory or its runs parent')
for path in paths:
    d=json.loads(path.read_text());print(f"\n{path.parent.name}: {d['status']}")
    print('selected:',d.get('selection',{}).get('selected_model'))
    print('model | status | test recall | test precision | test FPR | validation recall')
    for name,r in d['models'].items():
        t=r.get('test',{});v=r.get('validation',{})
        def pct(value):return '—' if value is None else f'{value:.3%}'
        print(' | '.join([name,r['status'],pct(t.get('recall')),pct(t.get('precision')),pct(t.get('fpr')),pct(v.get('recall'))]))
