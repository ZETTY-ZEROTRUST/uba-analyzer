"""Cloud-only RBA resume/fresh runner; never trains on a Mac/local runtime."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import threading
import time
import urllib.request


def copy_atomic(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary=destination.with_name(destination.name+'.copying')
    shutil.copy2(source, temporary);temporary.replace(destination)


def backup(source, destination):
    if not source.exists():return
    # Publish commit markers last, after the files they reference are durable.
    markers={name:(source/name).read_bytes() for name in ('study.json','dataset.json') if (source/name).exists()}
    for path in source.rglob('*'):
        if path.is_file() and path.name not in markers and path.suffix not in ('.tmp','.copying') and '__pycache__' not in path.parts:
            dest=destination/path.relative_to(source)
            if not dest.exists() or path.stat().st_size!=dest.stat().st_size or path.stat().st_mtime>dest.stat().st_mtime:
                copy_atomic(path,dest)
    destination.mkdir(parents=True,exist_ok=True)
    for name,content in markers.items():
        temporary=destination/(name+'.copying');temporary.write_bytes(content);temporary.replace(destination/name)


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(4*1024*1024),b''):h.update(block)
    return h.hexdigest()


def validate_runtime(checkpoint_python=None):
    if platform.system() != 'Linux' or not os.environ.get('COLAB_RELEASE_TAG'):
        raise SystemExit('Google-hosted Colab runtime required; local training is disabled')
    current = tuple(sys.version_info[:2])
    if current not in ((3, 12), (3, 13)):
        raise SystemExit('Python 3.12 or 3.13 required')
    if checkpoint_python is not None:
        try:
            previous = tuple(int(x) for x in checkpoint_python.split('.')[:2])
        except (AttributeError, ValueError):
            raise SystemExit('invalid checkpoint Python version')
        if previous != current:
            raise SystemExit('checkpoint Python minor mismatch; use its Python version or mode=fresh')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',choices=['resume','fresh'],required=True)
    p.add_argument('--checkpoint',type=Path)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--backup',type=Path,required=True)
    args=p.parse_args()
    validate_runtime()
    if args.mode == 'resume':
        if args.checkpoint is None:
            raise SystemExit('checkpoint required')
        checkpoint_manifest = json.loads((args.checkpoint/'runs/rba/study.json').read_text())
        validate_runtime(checkpoint_manifest['environment']['python'])
    if args.output.exists():raise SystemExit('use a new output directory; resume from a checkpoint copy')
    root=Path(__file__).resolve().parents[2]
    output=args.output;output.mkdir(parents=True)
    env=dict(os.environ,OMP_NUM_THREADS='2',OPENBLAS_NUM_THREADS='2',MKL_NUM_THREADS='2',PYTHONDONTWRITEBYTECODE='1')
    if args.mode=='resume':
        if args.checkpoint is None:raise SystemExit('checkpoint required')
        prepared=output/'prepared'/'rba';run=output/'runs'/'rba'
        shutil.copytree(args.checkpoint/'prepared'/'rba',prepared)
        shutil.copytree(args.checkpoint/'runs'/'rba',run,ignore=shutil.ignore_patterns('*.tmp','__pycache__'))
        manifest=json.loads((run/'study.json').read_text())
        if manifest['status'] not in ('STOPPED_BY_USER','FAILED','RUNNING'):
            raise SystemExit('expected interrupted study checkpoint')
        # Use exact source bytes from the original run, not changed inference code.
        source=output/'runtime_source'/'zetty_uba'
        shutil.copytree(run/'source_snapshot',source)
        h=hashlib.sha256()
        for path in sorted(source.rglob('*.py')):
            h.update(str(path.relative_to(source)).encode()+b'\0'+path.read_bytes()+b'\0')
        if h.hexdigest()!=manifest['code_sha256']:raise SystemExit('snapshot checksum mismatch')
        from importlib.metadata import version
        current={'python':platform.python_version(),'machine':platform.machine(),'thread_limit':2,
                 'packages':{key:version(key) for key in manifest['environment']['packages']}}
        if current['packages']!=manifest['environment']['packages']:raise SystemExit('dependency mismatch')
        # Integrity check before the trusted joblib artifacts can be loaded by runner.
        for result in manifest['models'].values():
            if 'artifact' in result:
                info=result['artifact'];path=run/info['file']
                if path.parent!=run or path.is_symlink() or sha(path)!=info['sha256']:
                    raise SystemExit('artifact checksum mismatch')
        manifest.setdefault('execution_history',[]).append({'previous_environment':manifest['environment'],
            'previous_status':manifest['status'],'resumed_environment':current,'resumed_epoch':time.time()})
        manifest['environment']=current;manifest['status']='RUNNING'
        (run/'study.json').write_text(json.dumps(manifest,indent=2)+'\n')
        env['PYTHONPATH']=str(source.parent)
    else:
        prepared=output/'prepared'/'rba';run=output/'runs'/'rba'
        env['PYTHONPATH']=str(root/'src')
        raw=output/'rba-dataset.zip'
        urllib.request.urlretrieve('https://zenodo.org/records/6782156/files/rba-dataset.zip?download=1',raw)
        # prepare_rba verifies original size/MD5 and CSV EOF/CRC itself.
        subprocess.run([sys.executable,'-m','zetty_uba.study','prepare','--source','rba',
                        '--input',str(raw),'--output',str(prepared)],cwd=root,env=env,check=True)
    finished=threading.Event();errors=[]
    def periodic():
        while not finished.wait(30):
            try:backup(run,args.backup/'runs'/'rba')
            except Exception as exc:errors.append(type(exc).__name__);print('backup error:',type(exc).__name__,flush=True)
    thread=threading.Thread(target=periodic,daemon=True);thread.start()
    code=1
    try:
        # Prepared arrays are essential for resume; copy once, not every heartbeat.
        backup(prepared,args.backup/'prepared'/'rba')
        code=subprocess.call([sys.executable,'-m','zetty_uba.study','train','--prepared',str(prepared),
                              '--output',str(run)],cwd=root,env=env)
    finally:
        finished.set();thread.join();backup(run,args.backup/'runs'/'rba')
        (args.backup/'cloud-execution.json').write_text(json.dumps({'returncode':code,'mode':args.mode,
            'platform':platform.platform(),'backup_errors':errors,'finished_epoch':time.time()},indent=2)+'\n')
    raise SystemExit(code)


if __name__=='__main__':main()
