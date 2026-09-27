"""Optional CUDA profile. Imports stay lazy so legacy CPU inference still works."""
import json
import os
import time
from dataclasses import dataclass, field

import numpy as np

PROFILE = 'colab-gpu-v1'


def candidates():
    # GPU models first: finish useful GPU work before inexpensive CPU baselines.
    return [
        {'id': f'xgb-cuda-d{depth}-r{rounds}-seed42-v1', 'kind': 'xgb',
         'depth': depth, 'rounds': rounds, 'max_bin': 128, 'seed': 42,
         'eta': .1, 'lambda': 3.0}
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
        data = cp.arange(64, dtype=cp.float32).reshape(32, 2)
        target = cp.asarray(np.arange(32) % 2, dtype=cp.float32)
        matrix = xgb.QuantileDMatrix(data, label=target, max_bin=16)
        model = xgb.train({'device':'cuda:0', 'tree_method':'hist', 'max_bin':16,
                           'max_depth':1, 'objective':'binary:logistic', 'nthread':cpu_workers()},
                          matrix, num_boost_round=1)
        device = require_cuda(model)
        if not bool(cp.isfinite(model.inplace_predict(data)).all()):
            raise RuntimeError('GPU smoke prediction is non-finite')
        cp.cuda.Stream.null.synchronize()
        name = properties['name']
        result = {'name':name.decode() if isinstance(name, bytes) else name,
                  'device':device, 'free_vram_bytes':int(free), 'total_vram_bytes':int(total),
                  'cuda_runtime':cp.cuda.runtime.runtimeGetVersion(),
                  'cuda_driver':cp.cuda.runtime.driverGetVersion(), 'cpu_workers':cpu_workers(),
                  'xgboost':xgb.__version__, 'cupy':cp.__version__, 'smoke':'passed'}
        del data, target, matrix, model
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


def fit(spec, x, labels, indices, *, workers, heartbeat):
    import cupy as cp
    import xgboost as xgb
    started = time.perf_counter()
    counts = np.bincount(labels[indices], minlength=2)
    if len(counts) != 2 or not np.all(counts > 0):
        return None, {'status':'SKIPPED', 'reason':'training_requires_both_task_classes'}
    free, _ = cp.cuda.runtime.memGetInfo()
    size = batch_rows(free, x.shape[1])

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
            input_data(data=cp.asarray(x[selection], dtype=cp.float32),
                       label=cp.asarray(truth, dtype=cp.float32),
                       weight=cp.asarray(len(indices) / (2 * counts[truth]), dtype=cp.float32))
            self.offset += len(selection)
            return True

    class Progress(xgb.callback.TrainingCallback):
        def after_iteration(self, model, epoch, evals_log):
            if epoch % 25 == 0:
                require_cuda(model)
                heartbeat(boosting_round=epoch + 1, total_rounds=spec['rounds'])
            return False

    matrix = xgb.QuantileDMatrix(Iterator(), max_bin=spec['max_bin'], nthread=workers,
                                max_quantile_batches=8)
    if matrix.num_row() != len(indices):
        raise RuntimeError('GPU training row coverage mismatch')
    booster = xgb.train({'device':'cuda:0', 'tree_method':'hist', 'objective':'binary:logistic',
                         'max_depth':spec['depth'], 'eta':spec['eta'], 'lambda':spec['lambda'],
                         'max_bin':spec['max_bin'], 'seed':spec['seed'], 'nthread':workers,
                         'subsample':1.0, 'colsample_bytree':1.0},
                        matrix, num_boost_round=spec['rounds'], callbacks=[Progress()])
    device = require_cuda(booster)
    cp.cuda.Stream.null.synchronize()
    fitted = GPUBooster(bytes(booster.save_raw(raw_format='ubj')), device, workers)
    result = {'status':'FITTED', 'fit_rows':len(indices), 'fit_seconds':time.perf_counter()-started,
              'fit_label_counts':{str(k):int(v) for k,v in enumerate(counts)},
              'full_eligible_training':True, 'device':device, 'batch_rows':size,
              'class_weight':'balanced using train labels only', 'native_format':'ubj',
              'epochs':1}
    del matrix, booster
    cp.get_default_memory_pool().free_all_blocks()
    return fitted, result


if __name__ == '__main__':
    print(json.dumps(preflight(), indent=2))
