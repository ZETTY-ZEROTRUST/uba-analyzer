"""Combined Log Format -> observed public-client 5-minute windows."""

from collections import Counter, defaultdict
from datetime import datetime
import math
from pathlib import Path
import re
from urllib.parse import urlsplit

import numpy as np

from .common import Observations, entity_key

SOURCE = 'online-shop-18895701'
NAMES = (
    'log_request_count', 'log_unique_paths', 'repeat_path_ratio',
    'log_body_bytes_sum', 'log_body_bytes_mean', 'log_body_bytes_max',
    'status_4xx_ratio', 'status_5xx_ratio', 'log_unique_methods',
    'log_interval_mean_seconds', 'interval_cv',
)
LINE = re.compile(
    r'^(?P<client>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<request>(?:\\.|[^"\\])*)" (?P<status>\d{3}) (?P<size>\d+|-) '
    r'"(?:\\.|[^"\\])*" "(?P<ua>(?:\\.|[^"\\])*)"\s*$'
)


def parse_line(line: str):
    if len(line) > 65536:
        raise ValueError('line_size_limit')
    match = LINE.fullmatch(line)
    if match is None:
        raise ValueError('invalid_combined_log')
    row = match.groupdict()
    try:
        time = datetime.strptime(row['time'], '%d/%b/%Y:%H:%M:%S %z').timestamp()
    except ValueError:
        raise ValueError('invalid_timestamp') from None
    request = row['request'].split()
    if len(request) != 3 or not request[2].startswith('HTTP/'):
        raise ValueError('invalid_request')
    if row['size'] == '-':
        raise ValueError('missing_response_bytes')
    status, size = int(row['status']), int(row['size'])
    if not 100 <= status <= 599 or size > 2**63 - 1:
        raise ValueError('invalid_http_measurement')
    try:
        path = urlsplit(request[1]).path
    except ValueError:
        raise ValueError('invalid_request_target') from None
    if not path.startswith('/') or len(path) > 8192:
        raise ValueError('invalid_request_target')
    return (entity_key(SOURCE, row['client'], row['ua']), time,
            request[0], path, status, size)


def load(path: Path, *, max_rows=500000, min_requests=2) -> Observations:
    if max_rows < 1 or min_requests < 2:
        raise ValueError('invalid_input_limits')
    groups = defaultdict(list)
    rejected = Counter()
    total, low, high, out_of_order, previous = 0, math.inf, -math.inf, 0, -math.inf
    with path.open(encoding='utf-8') as stream:
        while line := stream.readline(65538):
            total += 1
            if total > max_rows or len(line) > 65536:
                raise ValueError('input_resource_limit')
            try:
                row = parse_line(line)
            except ValueError as exc:
                rejected[str(exc)] += 1
                continue
            entity, time, *_ = row
            low, high = min(low, time), max(high, time)
            out_of_order += time < previous
            previous = time
            groups[(int(time // 300) * 300, entity)].append(row)
    x, times, entities = [], [], []
    excluded = Counter()
    duplicate_observations = 0
    for (start, entity), rows in sorted(groups.items()):
        if start < low or start + 300 > high:
            excluded['capture_boundary'] += 1
            continue
        if len(rows) < min_requests:
            excluded['insufficient_requests'] += 1
            continue
        # Identical second-resolution requests can be real repeats; do not dedupe
        # without a source event id. They are contained in the same split/window.
        duplicate_observations += len(rows) - len(set(rows))
        rows.sort(key=lambda row: row[1])
        count = len(rows)
        intervals = np.diff([row[1] for row in rows])
        mean_interval = float(intervals.mean())
        body = [row[5] for row in rows]
        paths = len({row[3] for row in rows})
        values = [
            math.log1p(count), math.log1p(paths), 1 - paths / count,
            math.log1p(sum(body)), math.log1p(sum(body) / count), math.log1p(max(body)),
            sum(400 <= row[4] < 500 for row in rows) / count,
            sum(row[4] >= 500 for row in rows) / count,
            math.log1p(len({row[2] for row in rows})), math.log1p(mean_interval),
            float(intervals.std()) / mean_interval if mean_interval else 0.0,
        ]
        x.append(values); times.append(start); entities.append(entity)
    audit = {
        'raw_rows': total, 'rejected_rows': dict(rejected), 'window_count': len(x),
        'excluded_windows': dict(excluded), 'out_of_order_rows': out_of_order,
        'identical_requests_retained': duplicate_observations,
        'label_policy': 'unknown; unsupervised contaminated-reference experiment',
        'identity': 'public pseudonymous client+UA; not authenticated user',
        'time_basis': 'UTC epoch seconds', 'window_seconds': 300,
        'completeness': 'capture boundaries excluded; collector gaps remain unknown',
        'session_leakage_limit': 'no session id; only nonoverlapping windows guaranteed',
    }
    return Observations(SOURCE, 'public-http-5min-v1', NAMES,
                        np.asarray(x, dtype=np.float64), np.asarray(times, dtype=np.int64),
                        np.asarray(entities), np.full(len(x), -1), audit, label_kind="unknown").validate()
