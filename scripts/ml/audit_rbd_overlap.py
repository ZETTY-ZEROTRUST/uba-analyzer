"""Report cross-task identity/time overlap without publishing identities."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import numpy as np
import pyarrow.parquet as pq


def audit(paths):
    paths=sorted(paths);seen={};pairs=Counter();counts={}
    for file_index,path in enumerate(paths):
        table=pq.read_table(path,columns=['user_id','entity','timestamp'],use_threads=False)
        stamps=table['timestamp'].to_numpy().astype('datetime64[ns]').astype(np.int64)
        keys=set()
        for user,entity,stamp in zip(table['user_id'].to_pylist(),table['entity'].to_pylist(),stamps):
            key=hashlib.sha256(json.dumps([str(user),str(entity),int(stamp)]).encode()).digest()
            keys.add(key)
        counts[path.name]={'raw_rows':len(stamps),'distinct_identity_time':len(keys),
                           'repeated_identity_time_rows':len(stamps)-len(keys)}
        for key in keys:
            previous=seen.get(key,0)
            for other in range(file_index):
                if previous&(1<<other):pairs[(paths[other].name,path.name)]+=1
            seen[key]=previous|(1<<file_index)
    return {'identity_policy':'raw published user_id/entity/exact timestamp hashed for audit only; no identities exported',
            'files':counts,'distinct_identity_time_across_all_files':len(seen),
            'overlap_pairs':[{'left':a,'right':b,'shared_identity_time':count} for (a,b),count in sorted(pairs.items())],
            'interpretation':'different task labels can legitimately differ for a shared window; do not pool as independent examples',
            'training_policy':'each file/source has an independent model and time split; no cross-task training pool'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=audit(args.directory.glob('*.parquet'))
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'files':len(result['files']),'overlapping_file_pairs':len(result['overlap_pairs']),
                      'unique_windows':result['distinct_identity_time_across_all_files']}))
