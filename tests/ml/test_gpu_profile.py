"""GPU contract tests use fake CUDA/XGBoost; never run local model training."""
import importlib.util
import json
import pickle
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

import numpy as np
from zetty_uba.study import gpu, runner
from zetty_uba.study.data import NumericSink

spec=importlib.util.spec_from_file_location('cloud_gpu_test',Path(__file__).resolve().parents[2]/'scripts/ml/colab_rba.py')
cloud=importlib.util.module_from_spec(spec);spec.loader.exec_module(cloud)


class FixedGPU:
    def use_gpu(self):self.gpu_enabled=True
    def score(self,x):return x[:,0]


class GPUContracts(unittest.TestCase):
    def test_candidates_and_resources(self):
        specs=gpu.candidates()
        self.assertEqual(len(specs),6)
        self.assertEqual([s['kind'] for s in specs],['xgb']*4+['if']*2)
        self.assertEqual(len({s['id'] for s in specs}),6)
        with patch.object(gpu.os,'sched_getaffinity',return_value={0,1},create=True):
            self.assertEqual(gpu.cpu_workers(),2)
        self.assertLessEqual(gpu.batch_rows(16*1024**3,17),262144)
        self.assertLessEqual(gpu.batch_rows(2*1024**3,100),gpu.batch_rows(16*1024**3,100))

    def test_fallback_rejected(self):
        model=Mock()
        model.save_config.return_value=json.dumps({'learner':{'generic_param':{'device':'cpu'}}})
        with self.assertRaisesRegex(RuntimeError,'fell back'):gpu.require_cuda(model)
        model.save_config.return_value=json.dumps({'learner':{'generic_param':{'device':'cuda:0'}}})
        self.assertEqual(gpu.require_cuda(model),'cuda:0')

    def test_portable_artifact_defaults_cpu_without_cupy(self):
        original=gpu.GPUBooster(b'test-native-bytes', 'cuda:0', 2, Mock())
        restored=pickle.loads(pickle.dumps(original))
        self.assertEqual(restored.device,'cpu');self.assertIsNone(restored._model)
        model=Mock();model.inplace_predict.return_value=np.array([.25])
        fake=SimpleNamespace(Booster=Mock(return_value=model))
        with patch.dict('sys.modules',{'xgboost':fake,'cupy':None}):
            np.testing.assert_array_equal(restored.score(np.array([[1.]],dtype=np.float32)),[.25])
        model.load_model.assert_called_once_with(bytearray(b'test-native-bytes'))
        model.set_param.assert_called_once_with({'device':'cpu','nthread':2})

    def test_gpu_iterator_uses_only_supplied_train_indices(self):
        calls=[];params=[]
        class DataIter:
            def __init__(self,**kw):pass
        class Matrix:
            def __init__(self,it,**kw):
                self.rows=0
                for _ in range(2):
                    it.reset();self.rows=0
                    def accept(**values):
                        calls.append(values);self.rows+=len(values['data'])
                    while it.next(accept):pass
            def num_row(self):return self.rows
        booster=Mock()
        booster.save_config.return_value=json.dumps({'learner':{'generic_param':{'device':'cuda:0'}}})
        booster.save_raw.return_value=b'native'
        def train(p,matrix,**kw):
            params.append(p)
            for callback in kw['callbacks']:callback.after_iteration(booster,0,{})
            return booster
        fake_xgb=SimpleNamespace(DataIter=DataIter,QuantileDMatrix=Matrix,train=train,
                                 callback=SimpleNamespace(TrainingCallback=object))
        fake_cp=SimpleNamespace(asarray=Mock(side_effect=AssertionError("v2 quantile must not stage GPU arrays")),float32=np.float32,
            cuda=SimpleNamespace(runtime=SimpleNamespace(memGetInfo=lambda:(4*1024**3,8*1024**3)),
                                 Stream=SimpleNamespace(null=SimpleNamespace(synchronize=lambda:None))),
            get_default_memory_pool=lambda:SimpleNamespace(free_all_blocks=lambda:None))
        x=np.arange(24,dtype=np.float32).reshape(12,2);labels=np.array([0,0,1,0,1,-1,0,1,0,1,0,0])
        indices=np.array([0,1,2,3])
        with patch.dict('sys.modules',{'cupy':fake_cp,'xgboost':fake_xgb}),patch.object(gpu,'batch_rows',return_value=2):
            model,result=gpu.fit(gpu.candidates()[0],x,labels,indices,workers=2,heartbeat=lambda **kw:None)
        self.assertEqual(result['fit_rows'],4)
        self.assertEqual(result['quantile_device'],'cpu')
        np.testing.assert_array_equal(np.concatenate([c['data'] for c in calls[:2]]),x[indices])
        np.testing.assert_allclose(np.concatenate([c['weight'] for c in calls[:2]]),[2/3,2/3,2,2/3])
        self.assertEqual(params[0]['device'],'cuda:0')
        self.assertEqual(result['device'],'cuda:0')

    def test_prepared_backup_excludes_cache_and_detects_corruption(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);src=root/'src';dst=root/'dst';src.mkdir()
            files={}
            for name in ('x','times','entities','labels'):
                path=src/(name+'.bin');path.write_bytes(name.encode())
                files[name]={'sha256':cloud.sha(path),'bytes':path.stat().st_size}
            (src/'dataset.json').write_text(json.dumps({'status':'COMPLETED','files':files}))
            (src/'history.sqlite').write_bytes(b'cache')
            cloud.copy_prepared(src,dst)
            self.assertEqual({p.name for p in dst.iterdir()},{'dataset.json','x.bin','times.bin','entities.bin','labels.bin'})
            (src/'x.bin').write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError,'checksum'):cloud.copy_prepared(src,root/'bad')
            self.assertFalse((root/'bad/dataset.json').exists())

    def test_profile_run_full_holdouts_without_training(self, profile=gpu.PROFILE):
        hardware={'cpu_workers':2,'free_vram_bytes':4*1024**3,'device':'cuda:0','smoke':'mock-only'}
        seen=[]
        def fake_fit(spec,x,labels,reference,supervised,scaler,**kw):
            self.assertIsNone(scaler)
            seen.append((spec['kind'],supervised.copy(),reference.copy()))
            return FixedGPU(),{'status':'FITTED','fit_seconds':0,'fit_rows':len(supervised if spec['kind']=='xgb' else reference)}
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);sink=NumericSink(root/'data',('feature',))
            for i in range(2000):sink.append([float(i%10==0)],i*300,'0'*64,1 if i%10==0 else 0)
            sink.finish({'source':'fixture','label_kind':'task','embargo_seconds':300,'feature_version':'fixture'})
            with patch.object(gpu,'preflight',return_value=hardware),patch.object(runner,'version',return_value='fixture'),patch.object(runner,'fit',side_effect=fake_fit),patch.object(runner,'fit_scaler') as scale:
                result=runner.run(root/'data',root/'run',profile=profile)
                scale.assert_not_called()
                self.assertEqual(result['status'],'COMPLETED')
                self.assertEqual(result['profile'],profile)
                self.assertTrue(result['selection']['frozen_before_test'])
                if profile == 'colab-gpu-v3':
                    self.assertEqual(result['threshold_tail'],.001)
                    self.assertFalse(result['selection']['deployment_ready'])
                    self.assertEqual(len(next(iter(result['models'].values()))['validation_operating_points']),3)
                self.assertTrue(all(r['status']=='EVALUATED' for r in result['models'].values()))
                self.assertEqual(len(seen),len(gpu.candidates(profile)))
                self.assertTrue(all(np.max(sup)<1000 for _,sup,_ in seen))
                runner.run(root/'data',root/'run',profile=profile)
                self.assertEqual(len(seen),len(gpu.candidates(profile)))

    def test_v3_run_full_holdouts_without_training(self):
        self.test_profile_run_full_holdouts_without_training(profile='colab-gpu-v3')

    def test_gpu_unavailable_stops_before_download_or_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with patch.object(cloud,'validate_runtime'),patch.object(cloud.sys,'argv',['runner','--mode','fresh','--profile',gpu.PROFILE,'--output',str(root/'out'),'--backup',str(root/'backup')]),patch.object(cloud.subprocess,'run',side_effect=RuntimeError('no GPU')),patch.object(cloud.urllib.request,'urlretrieve') as download:
                with self.assertRaisesRegex(RuntimeError,'no GPU'):cloud.main()
                download.assert_not_called()
            self.assertFalse((root/'out').exists())

    def test_cpu_checkpoint_cannot_resume_as_gpu(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);run=root/'checkpoint/runs/rba';run.mkdir(parents=True)
            (run/'study.json').write_text(json.dumps({'environment':{'python':'3.13.15'}}))
            with patch.object(cloud,'validate_runtime'),patch.object(cloud.sys,'argv',['runner','--mode','resume','--profile',gpu.PROFILE,'--checkpoint',str(root/'checkpoint'),'--output',str(root/'out'),'--backup',str(root/'backup')]),patch.object(cloud.subprocess,'run') as process:
                with self.assertRaisesRegex(SystemExit,'profile mismatch'):cloud.main()
                process.assert_not_called()
            self.assertFalse((root/'out').exists())

    def test_gpu_scoring_and_cpu_fallback_detection(self):
        backend=Mock();backend.inplace_predict.return_value=np.array([.75],dtype=np.float32)
        backend.save_config.return_value=json.dumps({'learner':{'generic_param':{'device':'cuda:0'}}})
        model=gpu.GPUBooster(b'native','cuda:0',2,backend)
        fake=SimpleNamespace(asarray=np.asarray,asnumpy=np.asarray,float32=np.float32)
        with patch.dict('sys.modules',{'cupy':fake,'xgboost':SimpleNamespace()}):
            np.testing.assert_allclose(model.score(np.array([[1.]])),[.75])
            backend.save_config.return_value=json.dumps({'learner':{'generic_param':{'device':'cpu'}}})
            with self.assertRaisesRegex(RuntimeError,'fell back'):model.score(np.array([[1.]]))
