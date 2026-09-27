"""Prespecified CPU models with full eligible-training coverage."""
from dataclasses import dataclass
import time

import numpy as np
from sklearn.cluster import MiniBatchKMeans
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.kernel_approximation import RBFSampler
from sklearn.linear_model import SGDOneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

BATCH=32768


def candidates():
    specs=[{'id':'standard-distance-v2','kind':'distance','seed':42}]
    for trees,samples in ((100,512),(200,2048)):
        for seed in (42,2026):
            specs.append({'id':f'if-t{trees}-s{samples}-seed{seed}','kind':'if','trees':trees,'samples':samples,'seed':seed})
    specs += [
        {'id':'sgdocsvm-linear-v2','kind':'sgd','kernel':'linear','epochs':2,'nu':.01,'seed':42},
        {'id':'sgdocsvm-rbf64-v2','kind':'sgd','kernel':'rbf','components':64,'gamma':.1,'epochs':2,'nu':.01,'seed':42},
        {'id':'kmeans32-v2','kind':'kmeans','clusters':32,'epochs':3,'seed':42},
        {'id':'kmeans128-v2','kind':'kmeans','clusters':128,'epochs':3,'seed':42},
        {'id':'hgb100-leaf15-v2','kind':'hgb','iterations':100,'leaves':15,'l2':1.,'seed':42},
        {'id':'hgb200-leaf31-v2','kind':'hgb','iterations':200,'leaves':31,'l2':3.,'seed':42},
        {'id':'rf100-depth12-v2','kind':'rf','trees':100,'depth':12,'leaf_min':10,'seed':42},
        {'id':'lof20-full-v2','kind':'lof','neighbors':20,'seed':42},
        {'id':'lof50-full-v2','kind':'lof','neighbors':50,'seed':42},
    ]
    return specs


def batches(x,indices,size=BATCH):
    for start in range(0,len(indices),size):
        yield np.asarray(x[indices[start:start+size]],dtype=np.float32)


def fit_scaler(x,reference):
    scaler=StandardScaler()
    for batch in batches(x,reference):scaler.partial_fit(batch)
    return scaler


@dataclass
class Fitted:
    kind:str
    model:object
    scaler:object
    mapper:object=None

    def transform(self,x):
        if self.kind in ('distance','sgd','kmeans','lof'):
            x=self.scaler.transform(x)
        if self.kind in ('sgd','kmeans'):
            x=np.clip(x,-10.,10.)
        if self.mapper is not None:x=self.mapper.transform(x)
        return x

    def score(self,x):
        x=self.transform(x)
        if self.kind=='distance':return np.max(np.abs(x),axis=1)
        if self.kind in ('if','lof'):return -self.model.score_samples(x)
        if self.kind=='sgd':return -self.model.decision_function(x)
        if self.kind=='kmeans':return self.model.transform(x).min(axis=1)
        return self.model.predict_proba(x)[:,1]


def fit(spec,x,labels,reference,supervised,scaler,heartbeat=lambda **kw:None,workers=2):
    kind=spec['kind'];seed=spec['seed'];mapper=None
    if kind == 'xgb':
        from .gpu import fit as fit_gpu
        return fit_gpu(spec,x,labels,supervised,workers=workers,heartbeat=heartbeat)
    indices=supervised if kind in ('hgb','rf') else reference
    if kind in ('hgb','rf') and len(np.unique(labels[indices]))!=2:
        return None,{'status':'SKIPPED','reason':'training_requires_both_task_classes'}
    if kind=='lof' and len(indices)>250000:
        return None,{'status':'SKIPPED','reason':'exact_LOF_full_training_exceeds_250k_quadratic_budget',
                     'eligible_rows':len(indices),'replacement':'full-data SGDOneClassSVM and MiniBatchKMeans'}
    started=time.perf_counter()
    if kind=='distance':model=None
    elif kind=='if':
        model=IsolationForest(n_estimators=spec['trees'],max_samples=min(spec['samples'],len(indices)),
                              random_state=seed,n_jobs=workers,contamination='auto').fit(x[indices])
    elif kind in ('sgd','kmeans'):
        if kind=='sgd':
            model=SGDOneClassSVM(nu=spec['nu'],random_state=seed,shuffle=True,average=True)
            if spec['kernel']=='rbf':
                mapper=RBFSampler(gamma=spec['gamma'],n_components=spec['components'],random_state=seed)
                mapper.fit(np.zeros((1,x.shape[1]),dtype=np.float32))
        else:
            model=MiniBatchKMeans(n_clusters=min(spec['clusters'],len(indices)),batch_size=BATCH,
                                 random_state=seed,n_init=1,reassignment_ratio=.01)
        rng=np.random.default_rng(seed)
        for epoch in range(spec['epochs']):
            processed=0
            for batch in batches(x,indices):
                batch=np.clip(scaler.transform(batch),-10.,10.)
                if mapper is not None:batch=mapper.transform(batch)
                batch=batch[rng.permutation(len(batch))]
                model.partial_fit(batch);processed+=len(batch)
                if processed%BATCH==0 and processed%(BATCH*32)==0:
                    heartbeat(epoch=epoch+1,processed_rows=processed,eligible_rows=len(indices))
    elif kind=='lof':
        model=LocalOutlierFactor(n_neighbors=min(spec['neighbors'],len(indices)-1),novelty=True,n_jobs=workers)
        model.fit(scaler.transform(x[indices]))
    else:
        truth=labels[indices];counts=np.bincount(truth,minlength=2)
        if kind=='hgb':
            model=HistGradientBoostingClassifier(max_iter=spec['iterations'],max_leaf_nodes=spec['leaves'],
                l2_regularization=spec['l2'],early_stopping=False,random_state=seed)
            weights=len(indices)/(2*counts[truth])
            model.fit(x[indices],truth,sample_weight=weights)
        else:
            model=RandomForestClassifier(n_estimators=spec['trees'],max_depth=spec['depth'],
                min_samples_leaf=spec['leaf_min'],class_weight='balanced',n_jobs=workers,random_state=seed)
            model.fit(x[indices],truth)
    fitted=Fitted(kind,model,scaler,mapper)
    return fitted,{'status':'FITTED','fit_rows':len(indices),'fit_seconds':time.perf_counter()-started,
                  'fit_label_counts':{str(int(k)):int(v) for k,v in zip(*np.unique(labels[indices],return_counts=True))},
                  'full_eligible_training':True,'epochs':spec.get('epochs',1)}
