"""Optional CUDA profile. Imports stay lazy so legacy CPU inference still works."""
import json
import os
import time
from dataclasses import dataclass, field

import numpy as np

PROFILE = 'colab-gpu-v2'


def candidates(profile=PROFILE):
    if profile == 'colab-gpu-v3':
        base = dict(candidates('colab-gpu-v2')[3], id='xgb-d6-r400-balanced-v3')
        result = [base]
        for depth in (8, 10, 12):
            for rounds, weighting in ((400, 'balanced'), (800, 'balanced'), (800, 'sqrt')):
                spec = dict(base, id=f'xgb-d{depth}-r{rounds}-{weighting}-v3',
                            depth=depth, rounds=rounds, weighting=weighting)
                if rounds == 800:
                    spec.update(eta=.05, **{'lambda':10., 'min_child_weight':10., 'max_delta_step':1.})
                result.append(spec)
        return result + candidates('colab-gpu-v2')[4:]
    # GPU models first: finish useful GPU work before inexpensive CPU baselines.
    return [
        {'id': f"xgb-cuda-d{depth}-r{rounds}-seed42-{profile.rsplit('-', 1)[-1]}", 'kind': 'xgb',
         'depth': depth, 'rounds': rounds, 'max_bin': 128, 'seed': 42,
         'eta': .1, 'lambda': 3.0, 'quantile_device': 'cpu' if profile == PROFILE else 'cuda'}
        for depth in (4, 6) for rounds in (200, 400)
    ] + [
        {'id': f'if-t100-s512-seed{seed}', 'kind': 'if', 'trees': 100,
         'samples': 512, 'seed': seed} for seed in (42, 2026)
    ]


def cpu_workers():
    try:
        count = len(os.sched_getaffinity(0))
    except AttributeError:
        count = os.cpu_count() or 1
    return max(1, min(count, 8))


def batch_rows(free_bytes, features):
    # Limit staging buffers; quantized dataset and tree workspaces need VRAM too.
    return max(1024, min(262144, int(free_bytes * .01 / max(4 * features * 8, 1))))


def require_cuda(booster):
    device = json.loads(booster.save_config())['learner']['generic_param']['device']
    if not device.startswith('cuda'):
        raise RuntimeError('GPU requested but XGBoost fell back to CPU; select a Colab GPU runtime')
    return device


def preflight():
    import cupy as cp
    import xgboost as xgb
    if cp.cuda.runtime.getDeviceCount() < 1:
        raise RuntimeError('No CUDA GPU: select a GPU runtime in Colab')
    with cp.cuda.Device(0):
        properties = cp.cuda.runtime.getDeviceProperties(0)
        if properties['major'] < 5:
            raise RuntimeError('GPU compute capability must be >= 5.0')
        free, total = cp.cuda.runtime.memGetInfo()
        if free < 2 * 1024**3:
            raise RuntimeError('Less than 2 GiB free VRAM; reconnect to a clean GPU runtime')
        # Exercise the same weighted CPU iterator / CUDA training path as the study.
        data = np.arange(128, dtype=np.float32).reshape(64, 2)
        target = (np.arange(64) % 7 == 0).astype(np.int8)
        spec = dict(candidates()[0], rounds=1, depth=1, max_bin=16)
        model, _ = fit(spec, data, target, np.arange(64), workers=cpu_workers(),
                       heartbeat=lambda **kw: None)
        if not np.isfinite(model.score(data)).all():
            raise RuntimeError('GPU smoke prediction is non-finite')
        device = require_cuda(model._model)
        cp.cuda.Stream.null.synchronize()
        name = properties['name']
        result = {'name':name.decode() if isinstance(name, bytes) else name,
                  'device':device, 'free_vram_bytes':int(free), 'total_vram_bytes':int(total),
                  'cuda_runtime':cp.cuda.runtime.runtimeGetVersion(),
                  'cuda_driver':cp.cuda.runtime.driverGetVersion(), 'cpu_workers':cpu_workers(),
                  'xgboost':xgb.__version__, 'cupy':cp.__version__, 'smoke':'passed'}
        del data, target, model
        cp.get_default_memory_pool().free_all_blocks()
        return result


@dataclass
class GPUBooster:
    """Native bytes are portable; an unpickled detector defaults to CPU."""
    raw: bytes
    device: str = 'cpu'
    workers: int = 2
    _model: object = field(default=None, repr=False)

    def __getstate__(self):
        return {'raw':self.raw, 'device':'cpu', 'workers':self.workers, '_model':None}

    def use_gpu(self):
        self.device = 'cuda:0'
        if self._model is not None:
            self._model.set_param({'device':self.device})

    def score(self, x):
        import xgboost as xgb
        if self._model is None:
            self._model = xgb.Booster()
            self._model.load_model(bytearray(self.raw))
            self._model.set_param({'device':self.device, 'nthread':self.workers})
        if self.device.startswith('cuda'):
            import cupy as cp
            values = self._model.inplace_predict(cp.asarray(x, dtype=cp.float32))
            require_cuda(self._model)
            return cp.asnumpy(values)
        return self._model.inplace_predict(np.asarray(x, dtype=np.float32))


def class_weights(counts, mode='balanced'):
    if mode not in ('balanced', 'sqrt'):
        raise ValueError('unknown weighting mode')
    ratio = float(counts[0]) / float(counts[1])
    positive = ratio if mode == 'balanced' else np.sqrt(ratio)
    scale = sum(counts) / (counts[0] + positive * counts[1])
    return np.array([scale, scale * positive], dtype=np.float64)


def fit(spec, x, labels, indices, *, workers, heartbeat):
    import cupy as cp
    import xgboost as xgb
    started = time.perf_counter()
    counts = np.bincount(labels[indices], minlength=2)
    if len(counts) != 2 or not np.all(counts > 0):
        return None, {'status':'SKIPPED', 'reason':'training_requires_both_task_classes'}
    weights = class_weights(counts, spec.get('weighting', 'balanced'))
    free, _ = cp.cuda.runtime.memGetInfo()
    size = batch_rows(free, x.shape[1])

    quantile_device = spec.get('quantile_device', 'cuda')
    array = np.asarray if quantile_device == 'cpu' else cp.asarray

    class Iterator(xgb.DataIter):
        def __init__(self):
            self.offset = 0
            super().__init__(release_data=True)

        def reset(self):
            self.offset = 0

        def next(self, input_data):
            if self.offset >= len(indices):
                return False
            selection = indices[self.offset:self.offset + size]
            truth = labels[selection]
            input_data(data=array(x[selection], dtype=np.float32),
                       label=array(truth, dtype=np.float32),
                       weight=array(weights[truth], dtype=np.float32))
            self.offset += len(selection)
            return True

    class Progress(xgb.callback.TrainingCallback):
        def after_iteration(self, model, epoch, evals_log):
            if epoch % 25 == 0:
                require_cuda(model)
                heartbeat(boosting_round=epoch + 1, total_rounds=spec['rounds'])
            return False

    heartbeat(phase='quantile', quantile_device=quantile_device)
    matrix = xgb.QuantileDMatrix(Iterator(), max_bin=spec['max_bin'], nthread=workers,
                                max_quantile_batches=8)
    if matrix.num_row() != len(indices):
        raise RuntimeError('GPU training row coverage mismatch')
    heartbeat(phase='boosting', device='cuda:0')
    booster = xgb.train({'device':'cuda:0', 'tree_method':'hist', 'objective':'binary:logistic',
                         'max_depth':spec['depth'], 'eta':spec['eta'], 'lambda':spec['lambda'],
                         'max_bin':spec['max_bin'], 'seed':spec['seed'], 'nthread':workers,
                         'subsample':1.0, 'colsample_bytree':1.0,
                         'min_child_weight':spec.get('min_child_weight',1.),
                         'max_delta_step':spec.get('max_delta_step',0.)},
                        matrix, num_boost_round=spec['rounds'], callbacks=[Progress()])
    device = require_cuda(booster)
    cp.cuda.Stream.null.synchronize()
    fitted = GPUBooster(bytes(booster.save_raw(raw_format='ubj')), device, workers)
    result = {'status':'FITTED', 'fit_rows':len(indices), 'fit_seconds':time.perf_counter()-started,
              'fit_label_counts':{str(k):int(v) for k,v in enumerate(counts)},
              'full_eligible_training':True, 'quantile_device':quantile_device, 'device':device, 'batch_rows':size,
              'class_weight':spec.get('weighting','balanced')+' using train labels only',
              'class_weights':weights.tolist(), 'native_format':'ubj',
              'epochs':1}
    del matrix, booster
    cp.get_default_memory_pool().free_all_blocks()
    return fitted, result


if __name__ == '__main__':
    print(json.dumps(preflight(), indent=2))
