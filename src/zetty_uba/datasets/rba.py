"""Bounded synthetic-login research adapter, causal before equal-time groups."""
from collections import Counter
import csv
from datetime import datetime, timezone
import math
from pathlib import Path, PurePosixPath
import zipfile

import numpy as np
from .common import Observations, entity_key

SOURCE = 'rba-6782156'
CONTEXT = ('Country', 'IP Address', 'Device Type', 'Browser Name and Version')
NAMES = ('log_prior_attempts', 'first_observation', 'log_seconds_since_previous',
         *tuple(n for key in ('country', 'ip', 'device', 'browser')
                for n in (f'{key}_new', f'{key}_prior_frequency')))
REQUIRED = ('User ID', 'Login Timestamp', 'Is Attack IP', 'Is Account Takeover', *CONTEXT)


def boolean(value):
    if value not in ('True', 'False', 'true', 'false'):
        raise ValueError('invalid_boolean')
    return value.lower() == 'true'


def parse(row):
    if any(row.get(key) is None or not row[key].strip() for key in REQUIRED):
        raise ValueError('missing_required_value')
    if any(len(value) > 8192 for value in row.values() if isinstance(value, str)):
        raise ValueError('field_resource_limit')
    try:
        time = datetime.fromisoformat(row['Login Timestamp'])
        # Source-naive convention for ordering, not proof of the original timezone.
        time = time.replace(tzinfo=timezone.utc) if time.tzinfo is None else time
        epoch = time.timestamp()
    except (ValueError, OverflowError):
        raise ValueError('invalid_timestamp') from None
    if not math.isfinite(epoch):
        raise ValueError('invalid_timestamp')
    ato, attack = boolean(row['Is Account Takeover']), boolean(row['Is Attack IP'])
    label = 1 if ato else -1 if attack else 0
    return entity_key(SOURCE, row['User ID']), epoch, tuple(row[key] for key in CONTEXT), label


def from_rows(rows, *, max_rows=250000):
    if not 100 <= max_rows <= 1000000:
        raise ValueError('row_limit_out_of_bounds')
    profiles, pending, x, times, entities, labels = {}, [], [], [], [], []
    previous, total, truncated, cutoff_excluded = None, 0, False, 0
    rejected = Counter()

    def flush():
        # All features for a tied-time group are computed before any history updates.
        for entity, time, context, label in pending:
            profile = profiles.get(entity)
            count, last, counts = profile if profile else (0, None, [Counter() for _ in CONTEXT])
            values = [math.log1p(count), float(count == 0), math.log1p(time-last) if last is not None else 0.]
            for value, frequency in zip(context, counts):
                values.extend([float(value not in frequency), frequency[value]/count if count else 0.])
            x.append(values); times.append(time); entities.append(entity); labels.append(label)
        for entity, time, context, _ in pending:
            count, _, counts = profiles.setdefault(entity, (0, None, [Counter() for _ in CONTEXT]))
            for value, frequency in zip(context, counts):
                frequency[value] += 1
            profiles[entity] = (count+1, time, counts)
        pending.clear()

    for row in rows:
        total += 1
        if total > max_rows:
            truncated = True
            cutoff_excluded = len(pending)
            pending.clear()
            break
        try:
            record = parse(row)
        except ValueError as exc:
            rejected[str(exc)] += 1
            continue
        time = record[1]
        if previous is not None and time < previous:
            raise ValueError('source_not_chronological')
        if previous is not None and time > previous:
            flush()
        pending.append(record)
        previous = time
    if not truncated:
        flush()
    audit = {
        'raw_rows_examined': min(total, max_rows), 'max_rows': max_rows,
        'sampling': 'first CSV rows; prefix only, not representative full-year sample',
        'prefix_truncated': truncated, 'cutoff_group_rows_excluded': cutoff_excluded,
        'rejected_rows': dict(rejected), 'observation_count': len(x),
        'label_counts': {str(k): v for k, v in Counter(labels).items()},
        'label_policy': 'ATO=1; attack-IP without ATO=-1 unknown; remaining=0 candidate negative',
        'time_basis': 'source ISO time, naive treated as UTC only for numeric ordering; timezone unverified',
        'history': 'all earlier accepted rows; equal timestamps excluded; no outcome/label filtering',
        'history_limit': 'starts empty at prefix start; prior attacks may contaminate context history',
        'excluded_features': ['Login Successful', 'Is Attack IP', 'Is Account Takeover', 'RTT', 'raw identifiers'],
        'deployment_limit': 'synthetic research only; no production IDS use',
        'identical_rows': 'retained without stable event identity; same timestamp stays within one split',
    }
    return Observations(SOURCE, 'synthetic-login-causal-v1', NAMES,
        np.asarray(x, dtype=np.float64), np.asarray(times), np.asarray(entities),
        np.asarray(labels), audit).validate()


def load(path: Path, *, max_rows=250000):
    # CLI verifies the entire downloaded ZIP against official size/checksum first.
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > 20:
            raise ValueError('archive_member_limit')
        candidates = [entry for entry in entries if entry.filename.lower().endswith('.csv')]
        if len(candidates) != 1:
            raise ValueError('expected_single_csv')
        member = candidates[0]
        parts = PurePosixPath(member.filename)
        if parts.is_absolute() or '..' in parts.parts or '\\' in member.filename:
            raise ValueError('unsafe_member_path')
        if member.flag_bits & 1 or member.file_size > 30 * 1024**3:
            raise ValueError('unsupported_archive_member')
        with archive.open(member) as stream:
            # Bounded lines prevent unbounded allocation; no extraction to disk.
            def lines():
                consumed = 0
                while line := stream.readline(65538):
                    consumed += len(line)
                    if len(line) > 65536 or consumed > 512 * 1024**2:
                        raise ValueError('decompression_budget_exceeded')
                    yield line.decode('utf-8-sig')
            reader = csv.DictReader(lines())
            if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames) or not set(REQUIRED) <= set(reader.fieldnames):
                raise ValueError('source_schema_mismatch')
            data = from_rows(reader, max_rows=max_rows)
            data.audit['archive_csv_bytes'] = member.file_size
            data.audit['archive_members'] = len(entries)
            return data
