"""CPU-bounded comparison with calibration-only thresholds and explicit metrics."""

from importlib.metadata import version
import hashlib
import json
from pathlib import Path
import platform
import resource
import shutil
from datetime import datetime, timezone
from time import perf_counter

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import RobustScaler
from threadpoolctl import threadpool_limits

from ..datasets.common import Observations, digest_file, write_json
from .split import chronological


class RobustDistance:
    """Train-only marginal median/IQR distance, a deliberately simple baseline."""

    def fit(self, x):
        self.median_ = np.median(x, axis=0)
        self.scale_ = np.maximum(np.quantile(x, .75, axis=0) - np.quantile(x, .25, axis=0), 1e-6)
        return self

    def anomaly_scores(self, x):
        return np.max(np.abs((x - self.median_) / self.scale_), axis=1)


def threshold_from_calibration(scores, tail_fraction=.01):
    scores = np.asarray(scores)
    if scores.ndim != 1 or len(scores) < 20 or not np.isfinite(scores).all():
        raise ValueError('invalid_calibration_scores')
    if not 0 < tail_fraction < .5:
        raise ValueError('invalid_tail_fraction')
    # A strict > comparison avoids an uncontrolled flag surge on tied scores.
    return float(np.quantile(scores, 1 - tail_fraction, method='higher'))


def metrics(scores, threshold, labels):
    scores, labels = np.asarray(scores), np.asarray(labels)
    if not np.isfinite(scores).all() or len(scores) != len(labels):
        raise ValueError('invalid_evaluation_input')
    predicted = scores > threshold
    known = labels != -1
    result = {'rows': len(scores), 'flagged': int(predicted.sum()),
              'flag_rate': float(predicted.mean()) if len(scores) else None,
              'labeled_rows': int(known.sum()), 'unknown_label_rows': int((~known).sum()),
              'confusion': None, 'precision': None, 'recall': None, 'fpr': None}
    if known.any():
        truth, p = labels[known] == 1, predicted[known]
        tp, fp = int((truth & p).sum()), int((~truth & p).sum())
        fn, tn = int((truth & ~p).sum()), int((~truth & ~p).sum())
        result.update(confusion={'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn},
                      precision=tp/(tp+fp) if tp+fp else None,
                      recall=tp/(tp+fn) if tp+fn else None,
                      fpr=fp/(fp+tn) if fp+tn else None)
    return result


def score(model, x, *, kind, scaler=None):
    batches = []
    for start in range(0, len(x), 1024):
        batch = x[start:start+1024]
        if scaler is not None:
            batch = scaler.transform(batch)
        if kind == 'robust_distance':
            batches.append(model.anomaly_scores(batch))
        elif kind == 'hist_gradient_boosting':
            batches.append(model.predict_proba(batch)[:, 1])
        else:
            batches.append(-model.score_samples(batch))
    return np.concatenate(batches) if batches else np.empty(0)


def code_hash():
    base = Path(__file__).resolve().parents[1]
    h = hashlib.sha256()
    for path in sorted(base.rglob('*.py')):
        h.update(str(path.relative_to(base)).encode() + b'\0' + path.read_bytes() + b'\0')
    return h.hexdigest()


def run(data: Observations, output: Path, *, source_manifest: dict, max_train=10000,
        seed=42, embargo_seconds=300, tail_fraction=.01, supervised=False):
    data.validate()
    if not 100 <= max_train <= 50000:
        raise ValueError('max_train_out_of_bounds')
    # Validate every precondition before creating an artifact directory.
    parts, split = chronological(data.times, embargo_seconds=embargo_seconds)
    labeled = data.label_kind == 'task'
    reference = data.labels == 0 if labeled else np.ones(len(data.times), dtype=bool)
    train = parts['train'][reference[parts['train']]]
    cal = parts['calibration'][reference[parts['calibration']]]
    if len(train) < 100 or len(cal) < 100:
        raise ValueError('insufficient_reference_rows')
    if len(train) > max_train:
        # Seeded selection inside the training period only; sort after selection.
        train = np.sort(np.random.default_rng(seed).choice(train, max_train, replace=False))
    if supervised and not labeled:
        raise ValueError('supervised_requires_labels')
    package = Path(__file__).resolve().parents[1]
    if output.resolve().is_relative_to(package):
        raise ValueError('output_inside_source_package')
    if output.exists():
        raise ValueError('output_must_not_exist')
    output.mkdir(parents=True)
    started = perf_counter()
    package = Path(__file__).resolve().parents[1]
    for source in package.rglob('*.py'):
        target = output / 'source_snapshot' / source.relative_to(package)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    ordered_feature_hash = hashlib.sha256(json.dumps(
        [data.source, data.feature_version, data.names], ensure_ascii=True).encode()).hexdigest()
    manifest = {
        'status': 'RUNNING', 'created_at': datetime.now(timezone.utc).isoformat(),
        'feature_dtype': str(data.x.dtype), 'observation_count': len(data.times),
        'format': 'zetty-offline-model/1', 'source': data.source,
        'source_manifest': source_manifest, 'feature_version': data.feature_version,
        'feature_names': list(data.names), 'feature_manifest_sha256': ordered_feature_hash,
        'code_sha256': code_hash(), 'seed': seed, 'split': split,
        'reference_policy': 'dataset label 0' if labeled else 'unlabeled contaminated reference; not reviewed normal',
        'reference_train_rows': len(train), 'reference_calibration_rows': len(cal),
        'tail_fraction': tail_fraction, 'comparison': 'score > threshold',
        'threshold_version': 'calibration-higher-quantile-v1',
        'environment': {'python': platform.python_version(), 'machine': platform.machine(),
                        'system': platform.system(), 'thread_limit': 2,
                        'packages': {name: version(name) for name in
                                     ('numpy', 'scipy', 'scikit-learn', 'joblib', 'threadpoolctl', 'pyarrow')}},
        'audit': data.audit, 'models': {},
        'deployment_status': 'offline_experiment_only; no production policy authorization',
    }
    write_json(output / 'manifest.json', manifest)
    np.savez_compressed(output / 'split_indices.npz', **parts, reference_train=train, reference_calibration=cal)
    manifest['split_sha256'] = digest_file(output / 'split_indices.npz')
    # No raw public identities/URLs are emitted in evaluation output.
    seen = set(data.entities[parts['train']])
    test = parts['test']
    seen_test = np.asarray([entity in seen for entity in data.entities[test]])
    kinds = ['robust_distance', 'isolation_forest', 'lof']
    if supervised:
        kinds.append('hist_gradient_boosting')
    with threadpool_limits(limits=2), joblib.parallel_backend('threading', n_jobs=2):
        for kind in kinds:
            start = perf_counter()
            scaler = None
            fit_rows = train
            if kind == 'robust_distance':
                model = RobustDistance().fit(data.x[train])
            elif kind == 'isolation_forest':
                model = IsolationForest(n_estimators=200, max_samples=min(512, len(train)),
                                        contamination='auto', random_state=seed, n_jobs=2).fit(data.x[train])
            elif kind == 'lof':
                scaler = RobustScaler().fit(data.x[train])
                model = LocalOutlierFactor(n_neighbors=min(35, len(train)-1), novelty=True,
                                          n_jobs=2).fit(scaler.transform(data.x[train]))
            else:
                fit_rows = parts['train'][data.labels[parts['train']] != -1]
                if len(np.unique(data.labels[fit_rows])) != 2:
                    manifest['models'][kind] = {'status': 'SKIPPED', 'reason': 'training_requires_both_classes'}
                    continue
                if len(fit_rows) > max_train:
                    # Preserve both classes, allocate half the budget per class.
                    rng = np.random.default_rng(seed)
                    fit_rows = np.sort(np.concatenate([
                        rng.choice(group, min(len(group), max_train//2), replace=False)
                        for group in [fit_rows[data.labels[fit_rows] == label] for label in (0, 1)]
                    ]))
                model = HistGradientBoostingClassifier(max_iter=100, max_leaf_nodes=15,
                    learning_rate=.1, early_stopping=False, l2_regularization=1., random_state=seed)
                counts = np.bincount(data.labels[fit_rows], minlength=2)
                weights = len(fit_rows) / (2 * counts[data.labels[fit_rows]])
                model.fit(data.x[fit_rows], data.labels[fit_rows], sample_weight=weights)
            fit_seconds = perf_counter() - start
            start = perf_counter()
            cal_scores = score(model, data.x[cal], kind=kind, scaler=scaler)
            threshold = threshold_from_calibration(cal_scores, tail_fraction)
            calibration_seconds = perf_counter() - start
            start = perf_counter()
            test_scores = score(model, data.x[test], kind=kind, scaler=scaler)
            inference_seconds = perf_counter() - start
            result = {
                'status': 'EVALUATED', 'fit_rows': len(fit_rows), 'threshold': threshold,
                'score_direction': 'higher_is_more_anomalous',
                'score_semantics': 'uncalibrated class score' if kind == 'hist_gradient_boosting' else 'anomaly ranking; not attack probability',
                'calibration': metrics(cal_scores, threshold, data.labels[cal]),
                'test': metrics(test_scores, threshold, data.labels[test]),
                'seen_entity_test': metrics(test_scores[seen_test], threshold, data.labels[test][seen_test]),
                'unseen_entity_test': metrics(test_scores[~seen_test], threshold, data.labels[test][~seen_test]),
                'seconds': {'fit': fit_seconds, 'calibration': calibration_seconds, 'test_inference': inference_seconds},
                'test_ms_per_row': 1000 * inference_seconds / len(test),
            }
            if not labeled:
                result['calibration']['metric_warning'] = 'flag_rate is NOT FPR: unknown labels'
            artifact = output / f'{kind}.joblib'
            joblib.dump({'model': model, 'scaler': scaler, 'threshold': threshold,
                         'feature_names': data.names, 'source': data.source,
                         'feature_version': data.feature_version,
                         'feature_manifest_sha256': ordered_feature_hash}, artifact, compress=3)
            result['artifact'] = {'file': artifact.name, 'sha256': digest_file(artifact),
                                  'trust': 'load only this locally generated artifact in a trusted directory'}
            manifest['models'][kind] = result
            write_json(output / 'manifest.json', manifest)
            print(json.dumps({'model': kind, 'status': result['status'], 'fit_seconds': fit_seconds,
                              'test_rows': len(test), 'test_flag_rate': result['test']['flag_rate']}), flush=True)
    manifest['training_evaluation_seconds'] = perf_counter() - started
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    manifest['process_peak_rss_mib'] = rss / (1024**2 if platform.system() == 'Darwin' else 1024)
    manifest['status'] = 'COMPLETED'
    write_json(output / 'manifest.json', manifest)
    return manifest
