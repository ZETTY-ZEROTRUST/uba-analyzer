"""Disk-backed numeric observations and full-file causal login preparation."""
from collections import Counter, OrderedDict
from contextlib import ExitStack
import csv
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import time
import zipfile

import numpy as np
from ..datasets.common import digest_file, verify_file
from ..datasets.rba import parse, NAMES as RBA_NAMES, REQUIRED, CONTEXT


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)+'\n')
    temporary.replace(path)


class NumericSink:
    def __init__(self, directory, names, batch_size=8192):
        self.directory, self.names, self.batch_size = Path(directory), tuple(names), batch_size
        self.directory.mkdir(parents=True, exist_ok=False)
        self.stack = ExitStack()
        self.files = {name:self.stack.enter_context((self.directory/(name+'.bin')).open('xb'))
                      for name in ('x','times','entities','labels')}
        self.buffer, self.count = [], 0

    def append(self, values, stamp, entity, label):
        if len(values)!=len(self.names) or not all(math.isfinite(v) for v in values):
            raise ValueError('invalid_numeric_feature')
        if not math.isfinite(stamp) or label not in (-1,0,1):
            raise ValueError('invalid_observation_metadata')
        self.buffer.append((values,stamp,bytes.fromhex(entity),label))
        if len(self.buffer)>=self.batch_size:self.flush()

    def flush(self):
        if not self.buffer:return
        x=np.asarray([r[0] for r in self.buffer],dtype='<f4')
        if not np.isfinite(x).all():raise ValueError('float32_overflow')
        arrays={'x':x, 'times':np.asarray([r[1] for r in self.buffer],dtype='<f8'),
                'entities':np.asarray([r[2] for r in self.buffer],dtype='S32'),
                'labels':np.asarray([r[3] for r in self.buffer],dtype='i1')}
        for name,array in arrays.items():self.files[name].write(array.tobytes())
        self.count+=len(self.buffer);self.buffer.clear()
        for stream in self.files.values():stream.flush()

    def close(self):
        self.flush();self.stack.close()

    def finish(self, metadata):
        self.close()
        if self.count==0:raise ValueError('empty_dataset')
        metadata.update(status='COMPLETED',rows=self.count,names=list(self.names),dtype='float32',
                        entity_storage='raw 32-byte SHA256 of source-namespaced public identity',
                        files={name:{'sha256':digest_file(self.directory/(name+'.bin')),
                                     'bytes':(self.directory/(name+'.bin')).stat().st_size}
                               for name in self.files})
        atomic_json(self.directory/'dataset.json',metadata)
        return metadata


def open_data(directory):
    directory=Path(directory)
    meta=json.loads((directory/'dataset.json').read_text())
    if meta['status']!='COMPLETED':raise ValueError('dataset_incomplete')
    n,d=meta['rows'],len(meta['names'])
    arrays={}
    for name,dtype,shape in [('x','<f4',(n,d)),('times','<f8',(n,)),('entities','S32',(n,)),('labels','i1',(n,))]:
        path=directory/(name+'.bin')
        if path.stat().st_size!=np.prod(shape)*np.dtype(dtype).itemsize:raise ValueError('dataset_size_mismatch')
        arrays[name]=np.memmap(path,dtype=dtype,shape=shape,mode='r')
    return arrays,meta


class History:
    """Exact past counts, bounded Python cache and SQLite spill, no eviction loss."""
    def __init__(self,path,capacity=100000):
        self.connection=sqlite3.connect(path)
        self.connection.execute('PRAGMA journal_mode=WAL')
        self.connection.execute('PRAGMA synchronous=NORMAL')
        self.connection.execute('PRAGMA cache_size=-65536')
        self.connection.execute('CREATE TABLE history (id TEXT PRIMARY KEY, body TEXT NOT NULL) WITHOUT ROWID')
        self.cache=OrderedDict();self.capacity=capacity;self.writes=0

    def get(self,key):
        if key in self.cache:
            self.cache.move_to_end(key);return self.cache[key]
        row=self.connection.execute('SELECT body FROM history WHERE id=?',(key,)).fetchone()
        value=json.loads(row[0]) if row else [0,None,[{} for _ in CONTEXT]]
        self.cache[key]=value
        if len(self.cache)>self.capacity:
            old,profile=self.cache.popitem(last=False)
            self.connection.execute('INSERT OR REPLACE INTO history VALUES (?,?)',(old,json.dumps(profile,separators=(',',':'))))
            self.writes+=1
            if self.writes%5000==0:self.connection.commit()
        return value

    def close(self):
        if self.connection is None:return
        # Persist every cached profile, including updates since last read.
        self.connection.executemany('INSERT OR REPLACE INTO history VALUES (?,?)',
            ((key,json.dumps(value,separators=(',',':'))) for key,value in self.cache.items()))
        self.connection.commit();self.connection.close();self.connection=None;self.cache.clear()


def emit_group(pending,history,sink,labels):
    for entity,stamp,context,label in pending:
        count,last,counts=history.get(entity)
        values=[math.log1p(count),float(count==0),math.log1p(stamp-last) if last is not None else 0.]
        for value,frequency in zip(context,counts):
            values.extend([float(value not in frequency),frequency.get(value,0)/count if count else 0.])
        sink.append(values,stamp,entity,label);labels[str(label)]+=1
    for entity,stamp,context,label in pending:
        profile=history.get(entity)
        profile[0]+=1;profile[1]=stamp
        for value,frequency in zip(context,profile[2]):frequency[value]=frequency.get(value,0)+1
    pending.clear()

def prepare_rba(path,directory,*,cache_users=100000):
    source=verify_file(Path(path),size=1093700330,md5='cc1b1078b3929650e6c08678caffcc57')
    started=time.perf_counter()
    sink=NumericSink(directory,RBA_NAMES)
    history=History(Path(directory)/'history.sqlite',cache_users)
    raw=0;rejected=Counter();labels=Counter();pending=[];previous=None
    try:
        with zipfile.ZipFile(path) as archive:
            members=[m for m in archive.infolist() if m.filename=='rba-dataset.csv']
            if len(members)!=1 or len(archive.infolist())>20:raise ValueError('archive_schema')
            member=members[0]
            if member.file_size!=9052907531:raise ValueError('csv_size_changed')
            with archive.open(member) as stream:
                def lines():
                    consumed=0
                    while line:=stream.readline(65538):
                        consumed+=len(line)
                        if len(line)>65536 or consumed>9052907531:raise ValueError('source_byte_limit')
                        yield line.decode('utf-8-sig')
                reader=csv.DictReader(lines())
                if not reader.fieldnames or not set(REQUIRED)<=set(reader.fieldnames):raise ValueError('source_schema')
                for row in reader:
                    raw+=1
                    if raw>50000000:raise ValueError('source_row_safety_limit')
                    try:record=parse(row)
                    except ValueError as exc:
                        rejected[str(exc)]+=1;continue
                    stamp=record[1]
                    if previous is not None and stamp<previous:raise ValueError('source_not_chronological')
                    if previous is not None and stamp>previous:emit_group(pending,history,sink,labels)
                    pending.append(record);previous=stamp
                    if len(pending)>100000:raise ValueError('timestamp_group_limit')
                    if raw%250000==0:
                        progress={'status':'RUNNING','raw_rows':raw,'written_rows':sink.count,
                                  'elapsed_seconds':time.perf_counter()-started,'rejected':dict(rejected)}
                        atomic_json(Path(directory)/'progress.json',progress)
                        print(json.dumps(progress),flush=True)
                emit_group(pending,history,sink,labels)
        history.close()
        return sink.finish({'source':'rba-6782156','feature_version':'synthetic-login-causal-f32-v2',
            'label_kind':'task','source_manifest':source,'embargo_seconds':3600,'previous_test_inspected':False,
            'builder_sha256':digest_file(Path(__file__)),'audit':{'coverage':'entire CSV to EOF; ZIP CRC checked',
            'raw_rows':raw,'rejected_rows':dict(rejected),'label_counts':dict(labels),
            'history':'exact all earlier accepted observations; no equal-time or label/outcome access',
            'history_cache_users':cache_users,'time_basis':'naive timestamps treated as UTC for ordering only',
            'identity':'synthetic public user, no authenticated service identity',
            'label_policy':'ATO=1; attack-IP without ATO=-1; other=0 candidate negative',
            'deployment':'synthetic research only, not productive IDS'},'preparation_seconds':time.perf_counter()-started})
    except BaseException:
        sink.close();history.close()
        atomic_json(Path(directory)/'progress.json',{'status':'FAILED','raw_rows':raw,'written_rows':sink.count})
        raise


def export_observations(data,directory,*,source_manifest,embargo,previous_test_inspected=False):
    data.validate();sink=NumericSink(directory,data.names)
    for i in np.argsort(data.times,kind='stable'):
        sink.append(data.x[i].tolist(),float(data.times[i]),str(data.entities[i]),int(data.labels[i]))
    return sink.finish({'source':data.source,'feature_version':data.feature_version+'-f32-v2',
        'label_kind':data.label_kind,'source_manifest':source_manifest,'audit':data.audit,
        'embargo_seconds':embargo,'previous_test_inspected':previous_test_inspected,
        'builder_sha256':digest_file(Path(__file__))})
