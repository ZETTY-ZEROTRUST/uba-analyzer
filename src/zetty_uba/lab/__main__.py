"""Bounded public replay CLI. Does not train or connect to Auth/ES/LLM."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import time

import numpy as np

from ..datasets.common import digest_file
from ..study.data import open_data
from .core import Detector, Journal, MAX_PAYLOAD, canonical, sha, validate

STREAM = 'zetty:lab:observations:v1'
GROUP = 'zetty-lab-v1'


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


def process_message(client, journal, detector, message_id, fields):
    raw = fields.get('payload', '') if set(fields) == {'payload'} else ''
    # Revision in receipt namespace permits explicit evaluation with a different pinned model.
    delivery = f'{STREAM}:{message_id}:{detector.revision}'
    outcome = journal.process(delivery, raw, detector)
    client.xack(STREAM, GROUP, message_id)
    return outcome


def worker(client, journal, detector, *, consumer='lab-worker', max_messages=1000,
           idle_seconds=10, claim_idle_ms=30000, after_commit_test_failure=False):
    from redis.exceptions import ResponseError
    if max_messages < 1 or idle_seconds < 1 or claim_idle_ms < 0:
        raise ValueError('invalid_worker_limits')
    try:
        client.xgroup_create(STREAM, GROUP, id='0-0', mkstream=True)
    except ResponseError as exc:
        if not str(exc).startswith('BUSYGROUP'):
            raise
    count = 0; idle_start = time.monotonic(); cursor = '0-0'
    while count < max_messages:
        claimed = client.xautoclaim(STREAM, GROUP, consumer, min_idle_time=claim_idle_ms,
                                    start_id=cursor, count=1)
        cursor, messages = claimed[:2]
        if not messages:
            values = client.xreadgroup(GROUP, consumer, {STREAM: '>'}, count=1, block=500)
            messages = values[0][1] if values else []
        if not messages:
            if time.monotonic()-idle_start >= idle_seconds:
                break
            continue
        for message_id, fields in messages:
            if after_commit_test_failure:
                journal.process(f'{STREAM}:{message_id}:{detector.revision}', fields.get('payload',''), detector)
                raise RuntimeError('injected_exit_after_commit_before_ack')
            process_message(client, journal, detector, message_id, fields)
            count += 1
        idle_start = time.monotonic()
    return {'processed_deliveries': count, **journal.summary()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    exp = sub.add_parser('export')
    for key in ('prepared','run','output'):exp.add_argument('--'+key, required=True, type=Path)
    exp.add_argument('--limit', type=int, default=20);exp.add_argument('--include-attacks', action='store_true')
    pub = sub.add_parser('publish');pub.add_argument('--input', required=True, type=Path)
    pub.add_argument('--redis-url', default='redis://redis-lab:6379/0')
    pub.add_argument('--max-messages', type=int, default=10000)
    for command in ('run-file', 'worker'):
        p = sub.add_parser(command)
        p.add_argument('--run', required=True, type=Path);p.add_argument('--manifest-sha256', required=True)
        p.add_argument('--model');p.add_argument('--database', required=True, type=Path)
        if command == 'run-file':p.add_argument('--input', required=True, type=Path)
        else:
            p.add_argument('--redis-url', default='redis://redis-lab:6379/0')
            p.add_argument('--max-messages', type=int, default=1000)
            p.add_argument('--idle-seconds', type=int, default=10)
            p.add_argument('--claim-idle-ms', type=int, default=30000)
            p.add_argument('--inject-exit-after-commit', action='store_true', help='local recovery test only')
    stat = sub.add_parser('inspect');stat.add_argument('--database', required=True, type=Path)
    args = parser.parse_args()
    if args.command == 'export':
        result = export(args.prepared, args.run, args.output, args.limit, args.include_attacks)
    elif args.command == 'inspect':
        result = Journal(args.database).summary()
    elif args.command == 'publish':
        from redis import Redis
        client = Redis.from_url(args.redis_url, decode_responses=True, socket_timeout=5)
        count = 0
        if not 1 <= args.max_messages <= 10000:raise ValueError('invalid_publish_limit')
        for raw in lines(args.input):
            if count >= args.max_messages:raise ValueError('publish_limit_exceeded')
            validate(json.loads(raw));client.xadd(STREAM, {'payload':raw});count += 1
        result = {'published': count, 'stream': STREAM}
    else:
        detector = Detector(args.run, args.manifest_sha256, args.model)
        journal = Journal(args.database)
        if args.command == 'run-file':
            for index, raw in enumerate(lines(args.input)):
                if index >= 10000:raise ValueError('file_limit_exceeded')
                journal.process(f'file:{sha(raw.encode())}:{detector.revision}', raw, detector)
            result = journal.summary()
        else:
            from redis import Redis
            client = Redis.from_url(args.redis_url, decode_responses=True, socket_timeout=5)
            result = worker(client, journal, detector, max_messages=args.max_messages,
                idle_seconds=args.idle_seconds, claim_idle_ms=args.claim_idle_ms,
                after_commit_test_failure=args.inject_exit_after_commit)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
