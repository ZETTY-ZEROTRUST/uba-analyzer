"""RBD24 Phishing desktop only; exclude identity and threat-indicator features."""

from collections import Counter
from pathlib import Path

import numpy as np

from .common import Observations, entity_key

SOURCE = 'rbd24-13787591-phishing-desktop'
NAMES = tuple(
    [f'{protocol}_interlog_time_q{q}' for protocol in ('dns', 'ssl', 'http') for q in range(1, 6)]
    + [f'mean_interlog_time_{protocol}_interlog_time' for protocol in ('dns', 'ssl', 'http')]
    + ['http_method_get_ratio', 'http_method_post_ratio', 'http_method_head_ratio',
       'http_status_200_ratio', 'http_status_400_ratio']
)


def load(path: Path, *, max_rows=250000, source=SOURCE) -> Observations:
    import pyarrow.parquet as pq
    parquet = pq.ParquetFile(path)
    if parquet.metadata.num_rows > max_rows:
        raise ValueError('source_row_limit')
    table = parquet.read(columns=[*NAMES, 'label', 'timestamp', 'user_id', 'entity'], use_threads=False)
    x = np.column_stack([table[name].to_numpy() for name in NAMES]).astype(np.float64)
    raw_times = table['timestamp'].to_numpy()
    if np.isnat(raw_times).any():
        raise ValueError('missing_timestamp')
    times = raw_times.astype('datetime64[s]').astype(np.int64)
    raw_labels = table['label'].to_pylist()
    if any(type(label) is not int or label not in (-1, 0, 1) for label in raw_labels):
        raise ValueError('invalid_label')
    labels = np.asarray(raw_labels)
    raw_ids = list(zip(table['user_id'].to_pylist(), table['entity'].to_pylist()))
    if any(user is None or entity is None for user, entity in raw_ids):
        raise ValueError('missing_identity')
    entities = np.asarray([entity_key(source, str(user), str(entity)) for user, entity in raw_ids])
    seen, keep, duplicates, conflicts = {}, [], 0, set()
    for i, (time, entity) in enumerate(zip(times, entities)):
        key = (int(time), str(entity))
        if key in seen:
            old = seen[key]
            if labels[old] != labels[i] or not np.array_equal(x[old], x[i], equal_nan=True):
                conflicts.add(key)
            else:
                duplicates += 1
        else:
            seen[key] = i; keep.append(i)
    selected = np.asarray([i for i in keep if (int(times[i]), str(entities[i])) not in conflicts], dtype=int)
    audit = {
        'raw_rows': len(times), 'deduplicated_windows': duplicates,
        'quarantined_conflicting_groups': len(conflicts),
        'quarantined_rows': sum((int(t), str(e)) in conflicts for t, e in zip(times, entities)),
        'raw_label_counts': {str(k): v for k, v in Counter(raw_labels).items()},
        'selected_columns': list(NAMES),
        'excluded_feature_groups': ['user_id', 'entity', 'label', 'timestamp',
                                    'all SMTP', 'compromised indicators', 'SSL alerts/versions'],
        'time_basis': 'source-naive timestamp ordered as published; timezone unverified',
        'window_width': 'not established from metadata; 24h split embargo is conservative, not proof',
        'label_policy': f'{source} task only; label 0 training, -1 excluded',
        'deployment_limit': 'offline benchmark only; feature units/window semantics need further audit',
    }
    return Observations(source, 'rbd-behavior-allowlist-v2', NAMES, x[selected], times[selected],
                        entities[selected], labels[selected], audit).validate()
