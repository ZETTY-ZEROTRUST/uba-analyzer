"""Four-way chronological selection, full holdouts, restartable model stages."""
import gc
import hashlib
import json
from importlib.metadata import version
from pathlib import Path
import platform
import resource
import shutil
import time

import joblib
import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score
from threadpoolctl import threadpool_limits

from ..datasets.common import digest_file
from ..training.benchmark import code_hash, metrics, threshold_from_calibration
from .data import open_data, atomic_json
from .models import candidates, fit, fit_scaler


def split_four(times,embargo):
    if embargo<0 or not np.isfinite(times).all():raise ValueError('invalid_split_input')
    unique=np.unique(times)
    if len(unique)<100:raise ValueError('insufficient_unique_times')
    a,b,c=(float(unique[int(len(unique)*fraction)]) for fraction in (.5,.65,.8))
    del unique
    parts={'train':np.flatnonzero(times<a),
           'calibration':np.flatnonzero((times>=a+embargo)&(times<b)),
           'validation':np.flatnonzero((times>=b+embargo)&(times<c)),
           'test':np.flatnonzero(times>=c+embargo)}
    if any(len(indices)<20 for indices in parts.values()):raise ValueError('insufficient_split_rows')
    return parts,{'method':'unique-time 50/15/15/20, source embargo at each boundary',
        'boundaries':[a,b,c],'embargo_seconds':embargo,'excluded_rows':len(times)-sum(map(len,parts.values())),
        'counts':{k:len(v) for k,v in parts.items()},
        'ranges':{k:[float(times[v].min()),float(times[v].max())] for k,v in parts.items()}}


def wilson(success,total):
    if not total:return None
    z=1.959963984540054;p=success/total;den=1+z*z/total
    center=(p+z*z/(2*total))/den
    half=z*np.sqrt(p*(1-p)/total+z*z/(4*total*total))/den
    return [max(0.,float(center-half)),min(1.,float(center+half))]


def evaluate(scores,threshold,labels):
    result=metrics(scores,threshold,labels)
    result['average_precision']=None;result['roc_auc']=None;result['wilson95']=None
    known=labels!=-1;truth=labels[known]
    if len(np.unique(truth))==2:
        result['average_precision']=float(average_precision_score(truth,scores[known]))
        result['roc_auc']=float(roc_auc_score(truth,scores[known]))
    if result['confusion'] is not None:
        c=result['confusion']
        result['wilson95']={'precision':wilson(c['tp'],c['tp']+c['fp']),
                            'recall':wilson(c['tp'],c['tp']+c['fn']),
                            'fpr':wilson(c['fp'],c['fp']+c['tn'])}
        result['interval_limit']='row-level binomial description; correlated windows are not independent incidents'
    return result


def score_all(model,x,indices,heartbeat=lambda **kw:None):
    started=time.perf_counter();scores=np.empty(len(indices),dtype=np.float64)
    for offset in range(0,len(indices),8192):
        values=np.asarray(model.score(x[indices[offset:offset+8192]]))
        if not np.isfinite(values).all():raise ValueError('non_finite_model_score')
        scores[offset:offset+len(values)]=values
        if offset and offset%(8192*128)==0:heartbeat(scored_rows=offset,total_rows=len(indices))
    return scores,time.perf_counter()-started


def select_model(results):
    eligible=[]
    for name,result in results.items():
        value=result.get('validation')
        if value and value['recall'] is not None and value['fpr'] is not None and value['fpr']<=.02:
            eligible.append((name,value))
    ranked=sorted(eligible,key=lambda item:(-item[1]['recall'],-(item[1]['precision'] or 0),item[1]['fpr'],item[0]))
    winner=ranked[0][0] if ranked else None
    selected=ranked[0][1] if ranked else None
    c=selected['confusion'] if selected else None
    return {'selected_model':winner,'validation_fpr_limit':.02,
            'rule':'maximize validation recall, then precision, then lower FPR, then stable model id',
            'eligible_ranking':[name for name,_ in ranked],
            'evidence':'limited: validation attacks <20' if c and c['tp']+c['fn']<20 else 'task-specific holdout' if c else 'no eligible labeled comparison',
            'selection_input':'validation only; no test metrics or scores used',
            'frozen_before_test':True}


def run(directory,output,*,specs=None):
    directory,output=Path(directory),Path(output)
    arrays,meta=open_data(directory)
    for name,info in meta['files'].items():
        if digest_file(directory/(name+'.bin'))!=info['sha256']:raise ValueError('dataset_checksum_mismatch')
    specs=candidates() if specs is None else specs
    package=Path(__file__).resolve().parents[1]
    if output.resolve().is_relative_to(package):raise ValueError('output_inside_source')
    identity={'dataset_sha256':digest_file(directory/'dataset.json'),'code_sha256':code_hash(),
              'candidates':specs,'format':'zetty-full-study/2','threshold_tail':.01}
    plan_hash=hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()
    if output.exists():
        existing=json.loads((output/'study.json').read_text())
        if existing['plan_sha256']!=plan_hash:raise ValueError('resume_plan_mismatch')
        if existing['status']=='COMPLETED':return existing
        manifest=existing
    else:
        output.mkdir(parents=True)
        for source in package.rglob('*.py'):
            target=output/'source_snapshot'/source.relative_to(package)
            target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
        manifest={'status':'RUNNING','plan_sha256':plan_hash,**identity,'dataset':meta,'models':{},
                  'environment':{'python':platform.python_version(),'machine':platform.machine(),'thread_limit':2,
                      'packages':{name:version(name) for name in ('numpy','scipy','scikit-learn','joblib','threadpoolctl','pyarrow')}}}
        atomic_json(output/'study.json',manifest)
    began=time.perf_counter();parts,split=split_four(arrays['times'],meta['embargo_seconds'])
    train=parts['train'];labels=arrays['labels'];x=arrays['x']
    reference=train[labels[train]==0] if meta['label_kind']=='task' else train
    calibration=parts['calibration'][labels[parts['calibration']]==0] if meta['label_kind']=='task' else parts['calibration']
    supervised=train[labels[train]!=-1]
    if len(reference)<100 or len(calibration)<100:raise ValueError('insufficient_reference_rows')
    np.savez_compressed(output/'split_indices.npz',**parts,reference_train=reference,reference_calibration=calibration)
    manifest.update(split=split,split_sha256=digest_file(output/'split_indices.npz'),
        eligible_reference_train=len(reference),eligible_reference_calibration=len(calibration),
        split_label_counts={key:{str(int(k)):int(v) for k,v in zip(*np.unique(labels[indices],return_counts=True))}
                            for key,indices in parts.items()},
        reference_policy='task candidate label0' if meta['label_kind']=='task' else 'unlabeled contaminated reference; NOT reviewed normal')
    def progress(**values):
        state={'source':meta['source'],'elapsed_seconds':time.perf_counter()-began,**values}
        atomic_json(output/'progress.json',state);print(json.dumps(state),flush=True)
    try:
        with threadpool_limits(2),joblib.parallel_backend('threading',n_jobs=2):
            progress(stage='fit_train_only_scaler',rows=len(reference))
            scaler=fit_scaler(x,reference)
            for spec in specs:
                name=spec['id'];old=manifest['models'].get(name,{})
                if old.get('status') in ('VALIDATED','EVALUATED','SKIPPED'):continue
                progress(stage='fit',model=name)
                model,result=fit(spec,x,labels,reference,supervised,scaler,
                    heartbeat=lambda **kw:progress(stage='fit',model=name,**kw))
                result['specification']=spec
                if model is None:
                    manifest['models'][name]=result;atomic_json(output/'study.json',manifest);continue
                artifact=output/(name+'.joblib');temporary=artifact.with_suffix('.tmp')
                joblib.dump({'model':model,'source':meta['source'],'features':meta['names'],
                             'feature_version':meta['feature_version'],'plan_sha256':plan_hash},temporary,compress=3)
                temporary.replace(artifact)
                result['artifact']={'file':artifact.name,'sha256':digest_file(artifact),'bytes':artifact.stat().st_size}
                progress(stage='calibrate',model=name)
                scores,seconds=score_all(model,x,calibration,
                    heartbeat=lambda **kw:progress(stage='calibrate',model=name,**kw))
                threshold=threshold_from_calibration(scores)
                result.update(threshold=threshold,threshold_rule='99% higher quantile; strict >',
                              calibration=evaluate(scores,threshold,labels[calibration]),calibration_seconds=seconds)
                del scores
                progress(stage='validate',model=name)
                scores,seconds=score_all(model,x,parts['validation'],
                    heartbeat=lambda **kw:progress(stage='validate',model=name,**kw))
                result.update(validation=evaluate(scores,threshold,labels[parts['validation']]),
                              validation_seconds=seconds,status='VALIDATED')
                manifest['models'][name]=result;atomic_json(output/'study.json',manifest)
                del scores,model;gc.collect()
            selection=select_model(manifest['models'])
            if (output/'selection.json').exists():
                if json.loads((output/'selection.json').read_text())!=selection:raise ValueError('selection_changed_after_freeze')
            else:atomic_json(output/'selection.json',selection)
            manifest['selection']=selection;atomic_json(output/'study.json',manifest)
            progress(stage='selection_frozen',selected=selection['selected_model'])
            train_entities=np.unique(arrays['entities'][train])
            test=parts['test'];seen=np.isin(arrays['entities'][test],train_entities)
            del train_entities
            for spec in specs:
                name=spec['id'];result=manifest['models'][name]
                if result['status'] in ('SKIPPED','EVALUATED'):continue
                artifact=output/result['artifact']['file']
                if digest_file(artifact)!=result['artifact']['sha256']:raise ValueError('own_artifact_checksum_mismatch')
                # Only artifacts just generated by this trusted job and matching its manifest.
                bundle=joblib.load(artifact)
                if bundle['plan_sha256']!=plan_hash:raise ValueError('artifact_plan_mismatch')
                progress(stage='final_test',model=name)
                scores,seconds=score_all(bundle['model'],x,test,
                    heartbeat=lambda **kw:progress(stage='final_test',model=name,**kw))
                result.update(test=evaluate(scores,result['threshold'],labels[test]),
                              seen_test=evaluate(scores[seen],result['threshold'],labels[test][seen]),
                              unseen_test=evaluate(scores[~seen],result['threshold'],labels[test][~seen]),
                              test_seconds=seconds,test_ms_per_row=1000*seconds/len(test),status='EVALUATED')
                manifest['models'][name]=result;atomic_json(output/'study.json',manifest)
                del scores,bundle;gc.collect()
        rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        manifest.update(status='COMPLETED',last_process_seconds=time.perf_counter()-began,
                        process_peak_rss_mib=rss/(1024**2 if platform.system()=='Darwin' else 1024))
        atomic_json(output/'study.json',manifest);progress(stage='COMPLETED')
        return manifest
    except BaseException as exc:
        manifest.update(status='FAILED',failure_type=type(exc).__name__)
        atomic_json(output/'study.json',manifest);raise
