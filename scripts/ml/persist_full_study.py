"""Copy completed public experiments only; verify content and never overwrite."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(4*1024*1024),b''):h.update(block)
    return h.hexdigest()


def persist(source,destination):
    if destination.resolve().is_relative_to(source.resolve()):raise ValueError('nested destination')
    studies=list((source/'runs').glob('*/study.json'))
    if len(studies)!=15:raise ValueError('expected studies including preserved failure')
    for path in studies:
        state=json.loads(path.read_text())['status']
        expected='FAILED' if path.parent.name=='Phishing_smartphone' else 'STOPPED_BY_USER' if path.parent.name=='rba' else 'COMPLETED'
        if state!=expected:raise ValueError('study not completed')
    selected=[]
    for directory in ('runs','data','logs'):
        selected.extend(p for p in (source/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.tmp')
    for directory in (source/'prepared').iterdir():
        if directory.is_dir():
            selected.extend(directory/name for name in ('dataset.json','x.bin','times.bin','entities.bin','labels.bin'))
    selected.extend(source/name for name in ('queue.json','rbd-files.json','rbd-overlap.json','user-stop.json'))
    files=[]
    for path in sorted(selected):
        if path.is_symlink():raise ValueError('unexpected symlink')
        relative=path.relative_to(source);target=destination/relative
        checksum=digest(path)
        target.parent.mkdir(parents=True,exist_ok=True)
        if not target.exists():
            if platform.system()=='Darwin':
                subprocess.run(['/bin/cp','-c',str(path),str(target)],check=True)
            else:shutil.copy2(path,target)
        if digest(target)!=checksum:raise ValueError(f'destination mismatch: {relative}')
        files.append({'path':str(relative),'bytes':target.stat().st_size,'sha256':checksum})
    result={'status':'VERIFIED_COPY_PARTIAL_STUDY','files':files,'excluded':'download chunks and completed preparation SQLite cache; not needed for inference/retraining on prepared arrays'}
    (destination/'persistence.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':'VERIFIED','files':len(files),'destination':str(destination)}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',required=True,type=Path);p.add_argument('--destination',required=True,type=Path)
    args=p.parse_args();persist(args.source,args.destination)
