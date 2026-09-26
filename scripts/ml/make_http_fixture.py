"""Create a small synthetic file pipeline demo; no network attack or model fit."""
import argparse
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import secrets

from zetty_log.__main__ import produce

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=False)
start=datetime(2026,9,27,tzinfo=timezone.utc);rows=[]
def add(client,seconds,path,size):
 rows.append({'request_id':f'{len(rows)+1:032x}','time':(start+timedelta(seconds=seconds)).isoformat(),
 'remote_addr':f'192.0.2.{client}','user_agent':'synthetic-file-demo','method':'GET','uri':path,'status':200,'body_bytes':size})
add(1,60,'/items',100);add(1,70,'/items',100)
for i in range(200):add(2,360+i/10,f'/items/{i}',2_000_000)
add(3,660,'/items',None);add(3,670,'/items',100)
add(4,80,'/items',100)
rows.append(dict(rows[0]))
raw=a.output/'synthetic-nginx.jsonl';raw.write_text(''.join(json.dumps(r)+'\n' for r in rows))
manifest=produce(raw,a.output/'capture',secrets.token_bytes(32),'fixture-ephemeral-v1',
 '2026-09-27T00:00:00Z','2026-09-27T00:15:00Z',True)
(a.output/'SCENARIOS.json').write_text(json.dumps({'scope':'synthetic file fixture; not real attack traffic',
 'windows':['two ordinary requests','200-request/400MB burst','missing bytes','single request'],
 'expected_quality':{'EVALUATED':2,'INCOMPLETE_WINDOW':1,'INSUFFICIENT_DATA':1},
 'model_flag_expectation':'measured, not forced; no performance claim'},indent=2)+'\n')
print(json.dumps(manifest))
