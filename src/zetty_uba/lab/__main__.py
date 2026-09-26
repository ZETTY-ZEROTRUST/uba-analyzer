"""Bounded public replay CLI. Does not train or connect to Auth/ES/LLM."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path

import numpy as np

from ..datasets.common import digest_file
from ..study.data import open_data
from .core import Detector, Journal, MAX_PAYLOAD, canonical, sha, validate

def lines(path):
    with Path(path).open() as stream:
        while True:
            line = stream.readline(MAX_PAYLOAD + 1)
            if not line:
                return
            if len(line.encode()) > MAX_PAYLOAD:
                raise ValueError('payload_too_large')
            yield line.rstrip('\n')


def export(prepared, run, output, limit, include_attacks=False):
    if not 1 <= limit <= 10000:
        raise ValueError('limit must be 1..10000')
    run, output = Path(run), Path(output)
    manifest = json.loads((run/'study.json').read_text())
    if manifest['status'] != 'COMPLETED':
        raise ValueError('study_not_completed')
    arrays, meta = open_data(prepared)
    if digest_file(Path(prepared)/'dataset.json') != manifest['dataset_sha256']:
        raise ValueError('prepared_dataset_mismatch')
    for key, value in meta['files'].items():
        if digest_file(Path(prepared)/(key+'.bin')) != value['sha256']:
            raise ValueError('prepared_checksum_mismatch')
    if digest_file(run/'split_indices.npz') != manifest['split_sha256']:
        raise ValueError('split_checksum_mismatch')
    with np.load(run/'split_indices.npz', allow_pickle=False) as splits:
        indices = splits['test']
    selected = indices[np.linspace(0, len(indices)-1, min(limit, len(indices)), dtype=int)]
    if include_attacks:
        attack_indices = indices[arrays['labels'][indices] == 1]
        # Integration coverage only. Never report its attack-enriched counts as full performance.
        selected = np.unique(np.concatenate([selected, attack_indices[:limit]]))
    labels = Counter()
    with output.open('x') as target:
        for index in selected:
            entity = bytes(arrays['entities'][index]).ljust(32, b'\0').hex()
            observation = {'schema_version': 'zetty-lab-observation/1', 'environment': 'public-replay',
                'observation_id': sha(canonical([manifest['dataset_sha256'], int(index)]).encode()),
                'source': meta['source'], 'feature_version': meta['feature_version'],
                'features': meta['names'], 'values': arrays['x'][index].tolist(), 'target_key': entity,
                'occurred_at': datetime.fromtimestamp(float(arrays['times'][index]), timezone.utc).isoformat().replace('+00:00','Z')}
            validate(observation);target.write(canonical(observation)+'\n')
            labels[str(int(arrays['labels'][index]))] += 1
    metadata = {'rows': len(selected), 'labels_for_audit_only': dict(labels),
        'selection': 'evenly spaced test rows plus first labeled attacks' if include_attacks else 'evenly spaced test rows',
        'scope': 'integration smoke; not a new performance evaluation', 'sha256': digest_file(output),
        'dataset_sha256': manifest['dataset_sha256'], 'manifest_sha256': digest_file(run/'study.json')}
    output.with_suffix('.meta.json').write_text(json.dumps(metadata, indent=2)+'\n')
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    exp = sub.add_parser('export')
    for key in ('prepared','run','output'):exp.add_argument('--'+key, required=True, type=Path)
    exp.add_argument('--limit', type=int, default=20);exp.add_argument('--include-attacks', action='store_true')
    p = sub.add_parser('run-file')
    p.add_argument('--run', required=True, type=Path);p.add_argument('--manifest-sha256', required=True)
    p.add_argument('--model');p.add_argument('--database', required=True, type=Path)
    p.add_argument('--input', required=True, type=Path)
    stat = sub.add_parser('inspect');stat.add_argument('--database', required=True, type=Path)
    args = parser.parse_args()
    if args.command == 'export':
        result = export(args.prepared, args.run, args.output, args.limit, args.include_attacks)
    elif args.command == 'inspect':
        result = Journal(args.database).summary()
    else:
        detector = Detector(args.run, args.manifest_sha256, args.model)
        journal = Journal(args.database)
        for index, raw in enumerate(lines(args.input)):
            if index >= 10000:raise ValueError('file_limit_exceeded')
            journal.process(f'file:{sha(raw.encode())}:{detector.revision}', raw, detector)
        result = journal.summary()
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
