import tempfile
import unittest
from pathlib import Path
import numpy as np
from zetty_uba.study.data import NumericSink
from zetty_uba.study.runner import split_four, select_model, evaluate, run
from zetty_uba.study.models import candidates

class FullStudy(unittest.TestCase):
    def test_four_part_groups_and_embargo(self):
        times=np.repeat(np.arange(1000)*300,2)
        parts,meta=split_four(times,600)
        values=[set(times[v]) for v in parts.values()]
        for i,a in enumerate(values):
            for b in values[i+1:]:self.assertFalse(a&b)
        for boundary,name in zip(meta['boundaries'],('calibration','validation','test')):
            self.assertGreaterEqual(times[parts[name]].min(),boundary+600)

    def test_selection_never_reads_final_test(self):
        a={'validation':{'recall':.8,'precision':.5,'fpr':.01,'confusion':{'tp':80,'fn':20}},'test':{'recall':0}}
        b={'validation':{'recall':.9,'precision':.8,'fpr':.05,'confusion':{'tp':90,'fn':10}},'test':{'recall':1}}
        self.assertEqual(select_model({'a':a,'b':b})['selected_model'],'a')
        a['test']['recall']=1;b['test']['recall']=0
        self.assertEqual(select_model({'a':a,'b':b})['selected_model'],'a')
        self.assertIsNone(select_model({})['selected_model'])

    def test_unknown_metric_and_sparse_interval(self):
        unknown=evaluate(np.array([0.,1.]),.5,np.array([-1,-1]))
        self.assertIsNone(unknown['roc_auc']);self.assertIsNone(unknown['wilson95'])
        rare=evaluate(np.array([0.,1.]),.5,np.array([0,1]))
        self.assertEqual(rare['recall'],1.)
        self.assertLess(rare['wilson95']['recall'][0],.5)

    def test_all_model_families_full_fit_and_resume(self):
        rng=np.random.default_rng(42);n=1400
        values=rng.normal(size=(n,3)).astype(np.float32)
        labels=np.zeros(n,dtype=int);labels[::7]=1;values[::7]+=4
        selected=candidates()
        with tempfile.TemporaryDirectory() as temp:
            data=Path(temp)/'data';sink=NumericSink(data,('a','b','c'))
            for i in range(n):sink.append(values[i],i*300,'0'*64,int(labels[i]))
            sink.finish({'source':'fixture','label_kind':'task','embargo_seconds':300,'feature_version':'fixture-v2'})
            result=run(data,Path(temp)/'run',specs=selected)
            self.assertEqual(result['status'],'COMPLETED')
            self.assertEqual(len(result['models']),14)
            for model in result['models'].values():
                self.assertEqual(model['status'],'EVALUATED')
                expected=result['split']['counts']['train'] if model['specification']['kind'] in ('hgb','rf') else result['eligible_reference_train']
                self.assertEqual(model['fit_rows'],expected)
                self.assertTrue(model['full_eligible_training'])
            self.assertTrue(result['selection']['frozen_before_test'])
            self.assertEqual(run(data,Path(temp)/'run',specs=selected),result)
