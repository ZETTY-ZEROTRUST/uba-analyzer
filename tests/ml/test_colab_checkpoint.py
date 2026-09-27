"""Cloud checkpoint backups tested with tiny files; never launch training."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('colab_runner',Path(__file__).resolve().parents[2]/'scripts/ml/colab_rba.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class ColabCheckpoint(unittest.TestCase):
    def test_commit_marker_is_written_after_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'src';dest=root/'dst';source.mkdir()
            (source/'study.json').write_text('{"status":"VALIDATED"}')
            (source/'model.joblib').write_bytes(b'opaque test bytes; not loaded')
            (source/'model.tmp').write_bytes(b'unfinished')
            original=module.copy_atomic
            def copy_checked(src,target):
                self.assertFalse((dest/'study.json').exists())
                original(src,target)
            with patch.object(module,'copy_atomic',copy_checked):module.backup(source,dest)
            self.assertEqual(json.loads((dest/'study.json').read_text())['status'],'VALIDATED')
            self.assertTrue((dest/'model.joblib').exists());self.assertFalse((dest/'model.tmp').exists())

    def test_copy_failure_does_not_publish_new_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'src';dest=root/'dst';source.mkdir();dest.mkdir()
            (source/'study.json').write_text('{"new":true}')
            (dest/'study.json').write_text('{"old":true}')
            (source/'model.joblib').write_bytes(b'fixture')
            with patch.object(module,'copy_atomic',side_effect=OSError('disk full')):
                with self.assertRaises(OSError):module.backup(source,dest)
            self.assertEqual(json.loads((dest/'study.json').read_text()),{'old':True})

    def test_local_runtime_rejected_before_creating_output(self):
        with patch.object(module.platform,'system',return_value='Darwin'), patch('sys.argv',
            ['colab_rba.py','--mode','fresh','--output','/must-not-create','--backup','/must-not-create-backup']):
            with self.assertRaisesRegex(SystemExit,'local training is disabled'):module.main()

    def test_supported_cloud_versions(self):
        with patch.object(module.platform, 'system', return_value='Linux'), patch.dict(module.os.environ, {'COLAB_RELEASE_TAG':'test'}):
            for version in [(3,12,13), (3,13,15)]:
                with patch.object(module.sys, 'version_info', version):
                    module.validate_runtime()
                    module.validate_runtime('.'.join(map(str, version)))
            with patch.object(module.sys, 'version_info', (3,14,0)):
                with self.assertRaisesRegex(SystemExit, '3.12 or 3.13'):module.validate_runtime()

    def test_cross_minor_resume_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);run=root/'checkpoint/runs/rba';run.mkdir(parents=True)
            (run/'study.json').write_text(json.dumps({'environment':{'python':'3.12.13'}}))
            with patch.object(module.platform,'system',return_value='Linux'), patch.dict(module.os.environ,{'COLAB_RELEASE_TAG':'test'}), patch.object(module.sys,'version_info',(3,13,15)), patch.object(module.sys,'argv',['runner','--mode','resume','--checkpoint',str(root/'checkpoint'),'--output',str(root/'out'),'--backup',str(root/'backup')]), patch.object(module.subprocess,'call') as train:
                with self.assertRaisesRegex(SystemExit,'minor mismatch'):module.main()
                train.assert_not_called()
            self.assertFalse((root/'out').exists())

    def test_linux_without_colab_is_rejected(self):
        with patch.object(module.platform,'system',return_value='Linux'), patch.dict(module.os.environ,{},clear=True):
            with self.assertRaisesRegex(SystemExit,'local training is disabled'):module.validate_runtime()

    def test_notebook_first_cell_accepts_313(self):
        notebook=json.loads((Path(__file__).resolve().parents[2]/'notebooks/zetty_rba_colab.ipynb').read_text())
        cells=[''.join(c['source']) for c in notebook['cells'] if c['cell_type']=='code']
        for source in cells:compile(source,'colab-cell','exec')
        with patch.object(module.platform,'system',return_value='Linux'), patch.dict(module.os.environ,{'COLAB_RELEASE_TAG':'test'}), patch.object(module.sys,'version_info',(3,13,15)):
            exec(compile(cells[0],'runtime-check','exec'),{})
        self.assertTrue(any("MODE = 'fresh'" in c for c in cells))
