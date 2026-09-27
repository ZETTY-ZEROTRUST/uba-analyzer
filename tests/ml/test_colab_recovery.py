"""Native failures / persistence regression tests; no actual training."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_gpu_profile import cloud


class Recovery(unittest.TestCase):
    def exercise(self, policy, code, backup_error=False):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'prepared';source.mkdir()
            files={}
            for name in ('x','times','entities','labels'):
                path=source/(name+'.bin');path.write_bytes(name.encode())
                files[name]={'sha256':cloud.sha(path),'bytes':path.stat().st_size}
            (source/'dataset.json').write_text(json.dumps({'status':'COMPLETED','files':files}))
            original={p.name:p.read_bytes() for p in source.iterdir()}
            output=root/'out';dest=root/'drive'
            argv=['runner','--mode','prepared','--prepared-local',str(source),'--output',str(output),
                  '--backup-policy',policy,'--backup',str(dest)]
            def child(command,**kw):
                self.assertEqual(command[command.index('--prepared')+1],str(source.resolve()))
                run=output/'runs/rba';run.mkdir(parents=True)
                (run/'study.json').write_text(json.dumps({'status':'RUNNING' if code else 'COMPLETED','models':{}}))
                (run/'model.bin').write_bytes(b'model')
                return code
            real_backup=cloud.backup
            def backup(src,dst):
                if backup_error:raise OSError('quota exceeded')
                real_backup(src,dst)
            with patch.object(cloud,'validate_runtime'),patch.object(cloud.sys,'argv',argv),patch.object(cloud.subprocess,'call',side_effect=child),patch.object(cloud,'backup',side_effect=backup) as copied:
                with self.assertRaises(SystemExit) as ended:cloud.main()
                self.assertEqual(ended.exception.code,128-code if code<0 else code)
                if policy=='local-only':copied.assert_not_called()
            self.assertEqual(original,{p.name:p.read_bytes() for p in source.iterdir()})
            self.assertFalse((output/'prepared').exists())
            manifest=json.loads((output/'runs/rba/study.json').read_text())
            record=json.loads((output/'cloud-execution.json').read_text())
            self.assertEqual(record['returncode'],code)
            if code:
                self.assertEqual(manifest['status'],'FAILED')
                self.assertEqual(manifest['failure']['returncode'],code)
            if policy=='local-only':self.assertFalse(dest.exists())
            elif not backup_error:
                self.assertTrue((dest/'runs/rba/model.bin').exists())
                self.assertFalse((dest/'prepared').exists())
            if backup_error:self.assertTrue(record['backup_errors'])

    def test_native_abort_marks_failed_without_drive_writes(self):self.exercise('local-only',-6)
    def test_success_results_only_excludes_prepared_arrays(self):self.exercise('results-only',0)
    def test_quota_error_does_not_hide_native_failure(self):self.exercise('results-only',-6,True)
    def test_quota_error_preserves_success_local_result(self):self.exercise('results-only',0,True)
