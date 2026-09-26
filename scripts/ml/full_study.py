"""Sequential per-source jobs; completed studies are resumable and isolated."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time


def save(path,value):
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n');temporary.replace(path)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--initial-data',type=Path,required=True)
    args=p.parse_args();root=args.root
    (root/'logs').mkdir(parents=True,exist_ok=True)
    (root/'runs').mkdir(exist_ok=True)
    files=json.loads((root/'rbd-files.json').read_text())
    jobs=[('online-shop','online-shop',args.initial_data/'online-shop.log')]
    jobs += [(Path(f['name']).stem,f['name'],root/'data/rbd24'/f['name']) for f in files]
    jobs += [('rba','rba',args.initial_data/'rba-dataset.zip')]
    state={'status':'RUNNING','started_utc_epoch':time.time(),'jobs':{},'execution':'sequential model jobs; threads2'}
    save(root/'queue.json',state)
    for slug,source,path in jobs:
        prepared=root/'prepared'/slug;output=root/'runs'/slug
        state['jobs'][slug]={'status':'RUNNING'};save(root/'queue.json',state)
        started=time.perf_counter()
        with (root/'logs'/(slug+'.log')).open('a') as log:
            try:
                if source=='rba' and prepared.exists() and not (prepared/'dataset.json').exists():
                    deadline=time.monotonic()+86400
                    while not (prepared/'dataset.json').exists():
                        progress=json.loads((prepared/'progress.json').read_text()) if (prepared/'progress.json').exists() else {}
                        if progress.get('status')=='FAILED' or time.monotonic()>deadline:raise RuntimeError('RBA preparation not completed')
                        time.sleep(30)
                if not (prepared/'dataset.json').exists():
                    subprocess.run([sys.executable,'-m','zetty_uba.study','prepare','--source',source,
                        '--input',str(path),'--output',str(prepared)],stdout=log,stderr=log,check=True)
                subprocess.run([sys.executable,'-m','zetty_uba.study','train',
                    '--prepared',str(prepared),'--output',str(output)],stdout=log,stderr=log,check=True)
                state['jobs'][slug]={'status':'COMPLETED','seconds':time.perf_counter()-started}
            except (subprocess.CalledProcessError,RuntimeError) as exc:
                state['jobs'][slug]={'status':'FAILED','error_type':type(exc).__name__,'log':str(root/'logs'/(slug+'.log'))}
        save(root/'queue.json',state);print(json.dumps({'source':slug,**state['jobs'][slug]}),flush=True)
    state['status']='COMPLETED' if all(j['status']=='COMPLETED' for j in state['jobs'].values()) else 'PARTIAL_FAILURE'
    state['finished_utc_epoch']=time.time();save(root/'queue.json',state)
    return 0 if state['status']=='COMPLETED' else 1


if __name__=='__main__':raise SystemExit(main())
