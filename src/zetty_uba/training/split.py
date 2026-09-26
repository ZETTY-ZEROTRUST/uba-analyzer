"""Timestamp-group splits: never split a shared window across partitions."""

import numpy as np


def chronological(times, *, embargo_seconds=300):
    times = np.asarray(times)
    if embargo_seconds < 0 or not np.isfinite(times).all():
        raise ValueError('invalid_split_input')
    unique = np.unique(times)
    if len(unique) < 10:
        raise ValueError('insufficient_unique_times')
    first, second = unique[int(len(unique) * .6)], unique[int(len(unique) * .8)]
    parts = {
        'train': np.flatnonzero(times < first),
        'calibration': np.flatnonzero((times >= first + embargo_seconds) & (times < second)),
        'test': np.flatnonzero(times >= second + embargo_seconds),
    }
    if any(len(rows) < 20 for rows in parts.values()):
        raise ValueError('insufficient_split_rows')
    return parts, {
        'method': 'unique-time 60/20/20 with boundary embargo',
        'first_boundary': float(first), 'second_boundary': float(second),
        'embargo_seconds': embargo_seconds,
        'excluded_rows': len(times) - sum(map(len, parts.values())),
        'counts': {name: len(rows) for name, rows in parts.items()},
        'ranges': {name: [float(times[rows].min()), float(times[rows].max())] for name, rows in parts.items()},
    }
