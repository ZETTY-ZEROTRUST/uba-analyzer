"""Pinned trusted artifact inference and transactional local result journal."""
import hashlib
import io
import json
import math
import re
import sqlite3
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

import joblib
import numpy as np
from threadpoolctl import threadpool_limits

MAX_PAYLOAD = 65536
OBSERVATION_KEYS = {'schema_version', 'environment', 'observation_id', 'source',
                    'feature_version', 'features', 'values', 'target_key', 'occurred_at'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate(observation):
    if not isinstance(observation, dict) or set(observation) != OBSERVATION_KEYS:
        raise ValueError('invalid_observation_fields')
    if observation['schema_version'] != 'zetty-lab-observation/1' or observation['environment'] != 'public-replay':
        raise ValueError('invalid_lab_contract')
    for key in ('observation_id', 'target_key'):
        if not isinstance(observation[key], str) or not re.fullmatch('[0-9a-f]{64}', observation[key]):
            raise ValueError('invalid_identity')
    for key in ('source', 'feature_version'):
        if not isinstance(observation[key], str) or not re.fullmatch('[A-Za-z0-9_.-]{1,160}', observation[key]):
            raise ValueError('invalid_version')
    stamp = observation['occurred_at']
    if not isinstance(stamp, str) or not stamp.endswith('Z'):
        raise ValueError('invalid_utc_time')
    try:
        datetime.fromisoformat(stamp[:-1] + '+00:00')
    except ValueError as exc:
        raise ValueError('invalid_utc_time') from exc
    names, values = observation['features'], observation['values']
    if not isinstance(names, list) or not 1 <= len(names) <= 256 or any(
        not isinstance(name, str) or not re.fullmatch('[A-Za-z0-9_.-]{1,160}', name) for name in names
    ) or len(set(names)) != len(names):
        raise ValueError('invalid_feature_names')
    if not isinstance(values, list) or len(values) != len(names) or any(
        type(value) not in (int, float) or not math.isfinite(value) or abs(value) > np.finfo(np.float32).max
        for value in values
    ):
        raise ValueError('invalid_feature_values')
    return observation


class Detector:
    """Only administrator-selected, checksum-pinned, locally trained artifacts."""
    def __init__(self, run, manifest_sha256, model_id=None):
        run = Path(run).resolve()
        raw = (run / 'study.json').read_bytes()
        if len(raw) > 5_000_000 or sha(raw) != manifest_sha256:
            raise ValueError('manifest_checksum_mismatch')
        manifest = json.loads(raw)
        if manifest['status'] != 'COMPLETED':
            raise ValueError('study_not_completed')
        self.model_id = model_id or manifest['selection']['selected_model']
        if not self.model_id:
            raise ValueError('explicit_model_required_for_unlabeled_source')
        result = manifest['models'][self.model_id]
        if result['status'] != 'EVALUATED':
            raise ValueError('model_not_evaluated')
        for package in ('numpy', 'scipy', 'scikit-learn', 'joblib'):
            if version(package) != manifest['environment']['packages'][package]:
                raise ValueError('dependency_version_mismatch')
        path = run / result['artifact']['file']
        if path.parent != run or path.is_symlink() or path.stat().st_size > 512 * 1024 * 1024:
            raise ValueError('invalid_artifact_path_or_size')
        content = path.read_bytes()
        if sha(content) != result['artifact']['sha256']:
            raise ValueError('artifact_checksum_mismatch')
        # No untrusted file upload. A checksum is integrity, not a trust decision.
        bundle = joblib.load(io.BytesIO(content))
        dataset = manifest['dataset']
        for key, expected in (('source', dataset['source']), ('features', dataset['names']),
                              ('feature_version', dataset['feature_version']),
                              ('plan_sha256', manifest['plan_sha256'])):
            if bundle[key] != expected:
                raise ValueError('artifact_contract_mismatch')
        self.bundle = bundle
        self.threshold = float(result['threshold'])
        if not math.isfinite(self.threshold) or result['threshold_rule'] != '99% higher quantile; strict >':
            raise ValueError('unsupported_threshold')
        self.revision = sha(canonical({'manifest': manifest_sha256, 'model': self.model_id}).encode())
        self.manifest_sha256 = manifest_sha256

    def detect(self, observation):
        validate(observation)
        status = 'EVALUATED'
        score = flag = None
        if any(observation[key] != self.bundle[key] for key in ('source', 'feature_version', 'features')):
            status = 'FEATURE_MISMATCH'
        else:
            try:
                with threadpool_limits(1), joblib.parallel_backend('threading', n_jobs=1):
                    model = self.bundle['model']
                    estimator = getattr(model, 'model', None)
                    if estimator is not None and hasattr(estimator, 'n_jobs'):
                        estimator.n_jobs = 1
                    values = np.asarray([observation['values']], dtype=np.float32)
                    scores = np.asarray(model.score(values)).reshape(-1)
                if len(scores) != 1 or not np.isfinite(scores).all():
                    raise ValueError('invalid_model_score')
                score = float(scores[0]); flag = score > self.threshold
            except Exception:
                status = 'MODEL_UNAVAILABLE'
        input_hash = sha(canonical(observation).encode())
        detection_id = sha(canonical([self.revision, observation['observation_id'], input_hash]).encode())
        return {'schema_version': 'zetty-lab-detection/1', 'detection_id': detection_id,
                'observation_id': observation['observation_id'], 'input_hash': input_hash,
                'environment': 'public-replay', 'source': observation['source'],
                'target_key': observation['target_key'], 'occurred_at': observation['occurred_at'],
                'model_id': self.model_id, 'model_revision': self.revision,
                'manifest_sha256': self.manifest_sha256, 'feature_version': self.bundle['feature_version'],
                'status': status, 'anomaly_score': score, 'threshold': self.threshold,
                'comparison': '>', 'is_anomaly': flag,
                'policy': 'REVIEW_ONLY' if flag else 'OBSERVE' if status == 'EVALUATED' else 'NOT_EVALUATED',
                'evidence': {'description': 'model score compared with frozen calibration threshold; not attack attribution'},
                'detected_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}


class Journal:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY, input_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS detections(id TEXT PRIMARY KEY, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS receipts(delivery TEXT PRIMARY KEY, raw_hash TEXT NOT NULL,
            outcome TEXT NOT NULL, detection_id TEXT);
        ''')

    def process(self, delivery, raw, detector):
        raw_hash = sha(raw.encode())
        old = self.db.execute('SELECT raw_hash,outcome FROM receipts WHERE delivery=?', (delivery,)).fetchone()
        if old:
            if old[0] != raw_hash:
                raise ValueError('delivery_content_changed')
            return old[1]
        try:
            if len(raw.encode()) > MAX_PAYLOAD:
                raise ValueError('payload_too_large')
            observation = validate(json.loads(raw))
            input_hash = sha(canonical(observation).encode())
        except (ValueError, TypeError, OverflowError):
            with self.db:
                self.db.execute('INSERT INTO receipts VALUES(?,?,?,NULL)', (delivery, raw_hash, 'INVALID_INPUT'))
            return 'INVALID_INPUT'
        # One bounded worker per database. Transaction precedes stream ACK.
        with self.db:
            old = self.db.execute('SELECT input_hash FROM observations WHERE id=?', (observation['observation_id'],)).fetchone()
            if old and old[0] != input_hash:
                self.db.execute('INSERT INTO receipts VALUES(?,?,?,NULL)', (delivery, raw_hash, 'ID_CONFLICT'))
                return 'ID_CONFLICT'
            self.db.execute('INSERT OR IGNORE INTO observations VALUES(?,?)', (observation['observation_id'], input_hash))
            detection_id = sha(canonical([detector.revision, observation['observation_id'], input_hash]).encode())
            old = self.db.execute('SELECT payload FROM detections WHERE id=?', (detection_id,)).fetchone()
            if old:
                result = json.loads(old[0])
            else:
                result = detector.detect(observation)
                self.db.execute('INSERT INTO detections VALUES(?,?)', (result['detection_id'], canonical(result)))
            self.db.execute('INSERT INTO receipts VALUES(?,?,?,?)', (delivery, raw_hash, result['status'], result['detection_id']))
        return result['status']

    def summary(self):
        return {'detections': self.db.execute('SELECT count(*) FROM detections').fetchone()[0],
                'receipts': dict(self.db.execute('SELECT outcome,count(*) FROM receipts GROUP BY outcome'))}
