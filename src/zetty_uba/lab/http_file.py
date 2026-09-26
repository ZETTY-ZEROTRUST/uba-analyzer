"""File HTTP observations -> causal-free 5min features -> frozen model inference.

Public HTTP model transfer is explicitly local-lab research, not a verified-user IDS.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

from zetty_log.http import MAX_LINE, canonical, digest, parse_json, utc, validate
from ..datasets.online_shop import NAMES, window_features
from .core import Detector


def epoch(value):return utc(value).timestamp()
def iso(value):return datetime.fromtimestamp(value,timezone.utc).isoformat().replace('+00:00','Z')
def hash_json(value):return hashlib.sha256(canonical(value).encode()).hexdigest()


def load_capture(directory):
    directory=Path(directory)
    if (directory/'capture.json').stat().st_size>65536:raise ValueError('manifest_size_limit')
    meta=parse_json((directory/'capture.json').read_text())
    if meta.get('schema_version')!='zetty-http-capture/1' or type(meta.get('complete')) is not bool:
        raise ValueError('capture_contract_mismatch')
    if meta.get('environment')!='local-lab':raise ValueError('local_lab_only')
    start,end=epoch(meta['capture_start']),epoch(meta['capture_end'])
    if start>=end:raise ValueError('invalid_capture_range')
    path=directory/'events.jsonl'
    if path.stat().st_size>64*1024*1024:raise ValueError('capture_size_limit')
    if digest(path)!=meta['events_sha256']:raise ValueError('capture_checksum_mismatch')
    events={};duplicate=0
    with path.open() as stream:
        count=0
        while raw:=stream.readline(MAX_LINE+1):
            count+=1
            if count>100000 or len(raw.encode())>MAX_LINE:raise ValueError('capture_row_limit')
            event=validate(parse_json(raw))
            if event['key_version']!=meta['key_version']:raise ValueError('key_version_mismatch')
            if not start<=epoch(event['occurred_at'])<end:raise ValueError('event_outside_capture')
            old=events.get(event['event_id'])
            if old:
                if old!=event:raise ValueError('event_id_content_conflict')
                duplicate+=1
            events[event['event_id']]=event
    if len(events)!=meta['events']:raise ValueError('event_count_mismatch')
    return list(events.values()),meta,duplicate


def detect(events,meta,detector):
    if detector.bundle['source']!='online-shop-18895701' or detector.bundle['features']!=list(NAMES) or detector.bundle['feature_version']!='public-http-5min-v1-f32-v2':
        raise ValueError('http_model_contract_mismatch')
    groups=defaultdict(list)
    for event in events:
        stamp=epoch(event['occurred_at']);groups[(int(stamp//300)*300,event['client_key'])].append(event)
    results=[]
    for (start,client),group in sorted(groups.items()):
        group.sort(key=lambda e:(epoch(e['occurred_at']),e['event_id']))
        capture_contract={key:meta[key] for key in ('capture_start','capture_end','complete','key_version','environment')}
        input_hash=hash_json({'events':group,'capture':capture_contract,'transfer':'local-http-to-public-http/1'})
        identifier=hash_json([detector.revision,client,start,input_hash])
        status='EVALUATED';reason=None
        if not meta['complete'] or start<epoch(meta['capture_start']) or start+300>epoch(meta['capture_end']):
            status,reason='INCOMPLETE_WINDOW','capture_not_complete'
        elif any(e['response_body_bytes'] is None for e in group):
            status,reason='INCOMPLETE_WINDOW','missing_response_bytes'
        elif len(group)<2:
            status,reason='INSUFFICIENT_DATA','minimum_two_requests'
        score=flag=None
        if status=='EVALUATED':
            rows=[(client,epoch(e['occurred_at']),e['method'],e['path_key'],e['status_code'],e['response_body_bytes']) for e in group]
            values=window_features(rows)
            # Mapping is explicit and result provenance remains LOCAL transfer.
            observation={'schema_version':'zetty-lab-observation/1','environment':'public-replay',
                'observation_id':identifier,'source':detector.bundle['source'],
                'feature_version':detector.bundle['feature_version'],'features':list(NAMES),
                'values':values,'target_key':client,'occurred_at':iso(start)}
            inferred=detector.detect(observation)
            status,score,flag=inferred['status'],inferred['anomaly_score'],inferred['is_anomaly']
        results.append({'schema_version':'zetty-file-detection/1','detection_id':identifier,
            'environment':'local-lab','data_origin':'local-http-transfer','input_source':'zetty-http-observation/1',
            'training_source':detector.bundle['source'],'transfer_version':'local-http-to-public-http/1',
            'target_type':'observed-client','target_key':client,'key_version':meta['key_version'],
            'window_start':iso(start),'window_end':iso(start+300),'input_hash':input_hash,
            'model_id':detector.model_id,'model_revision':detector.revision,
            'feature_version':detector.bundle['feature_version'],'manifest_sha256':detector.manifest_sha256,
            'status':status,'reason':reason,'anomaly_score':score,'threshold':detector.threshold,
            'is_anomaly':flag,'comparison':'>','evidence':{'requests':len(group),
            'meaning':'observed traffic deviation; not attack probability or authenticated-user attribution'}})
    return results


def pipeline(capture,run,manifest_sha256,model,output):
    output=Path(output);events,meta,duplicate=load_capture(capture)
    detector=Detector(run,manifest_sha256,model)
    results=detect(events,meta,detector)
    output.mkdir(parents=True,exist_ok=True)
    connection=sqlite3.connect(output/'detections.sqlite')
    connection.execute('PRAGMA synchronous=FULL')
    connection.execute('CREATE TABLE IF NOT EXISTS detections(id TEXT PRIMARY KEY,payload TEXT NOT NULL)')
    with connection:
        for result in results:
            payload=canonical(result)
            old=connection.execute('SELECT payload FROM detections WHERE id=?',(result['detection_id'],)).fetchone()
            if old and old[0]!=payload:raise ValueError('detection_id_content_conflict')
            connection.execute('INSERT OR IGNORE INTO detections VALUES(?,?)',(result['detection_id'],payload))
    # Atomic complete export; database is authoritative if export is interrupted.
    target=output/'detections.jsonl';temporary=output/'detections.jsonl.tmp'
    with temporary.open('w') as stream:
        for row in connection.execute('SELECT payload FROM detections ORDER BY id'):stream.write(row[0]+'\n')
    temporary.replace(target)
    count=connection.execute('SELECT count(*) FROM detections').fetchone()[0];connection.close()
    summary={'status':'COMPLETED','events':len(events),'duplicate_events_in_file':duplicate,
        'windows':len(results),'quality':dict(Counter(r['status'] for r in results)),
        'flagged_windows':sum(r['is_anomaly'] is True for r in results),'persisted_detections':count,
        'training_executed':False,'redis_used':False,'scope':'local HTTP transfer experiment; no attack ground truth'}
    (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    return summary


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('capture','run','output'):p.add_argument('--'+key,required=True,type=Path)
    p.add_argument('--manifest-sha256',required=True);p.add_argument('--model',required=True)
    args=p.parse_args();print(json.dumps(pipeline(args.capture,args.run,args.manifest_sha256,args.model,args.output)))

if __name__=='__main__':main()
