"""Bounded input validation and numeric observations, without model loading."""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

import numpy as np


@dataclass
class Observations:
    source: str
    feature_version: str
    names: tuple[str, ...]
    x: np.ndarray
    times: np.ndarray
    entities: np.ndarray
    labels: np.ndarray  # -1 = unknown; 0/1 are dataset-specific labels
    audit: dict
    label_kind: str = "task"  # task labels remain task labels even if every row is unknown

    def validate(self):
        n = len(self.times)
        if self.label_kind not in ("task", "unknown"):
            raise ValueError("invalid_label_kind")
        if self.label_kind == "unknown" and np.any(self.labels != -1):
            raise ValueError("unknown_source_has_labels")
        if not n or self.x.shape != (n, len(self.names)):
            raise ValueError('empty_or_misaligned_observations')
        if len(set(self.names)) != len(self.names):
            raise ValueError('duplicate_feature_name')
        if len(self.entities) != n or len(self.labels) != n:
            raise ValueError('misaligned_identity_or_label')
        if not np.isfinite(self.x).all() or not np.isfinite(self.times).all():
            raise ValueError('non_finite_observation')
        if not np.isin(self.labels, [-1, 0, 1]).all():
            raise ValueError('invalid_label')
        return self


def digest_file(path: Path, algorithm='sha256') -> str:
    digest = hashlib.new(algorithm)
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verify_file(path: Path, *, size: int, md5: str) -> dict:
    if not path.is_file() or path.stat().st_size != size:
        raise ValueError('source_size_mismatch')
    if digest_file(path, 'md5') != md5:
        raise ValueError('source_checksum_mismatch')
    return {'bytes': size, 'md5': md5, 'sha256': digest_file(path)}


def entity_key(source: str, *parts: str) -> str:
    # Extra namespacing for already-public pseudonyms; not an anonymization claim.
    return hashlib.sha256(json.dumps([source, *parts], ensure_ascii=True).encode()).hexdigest()


def write_json(path: Path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n')
