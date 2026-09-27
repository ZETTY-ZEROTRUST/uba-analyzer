import unittest
import numpy as np
from zetty_uba.study.gpu import candidates, class_weights
from zetty_uba.study.runner import select_model

class DepthTuning(unittest.TestCase):
    def test_candidates_and_legacy(self):
        self.assertEqual(len(candidates('colab-gpu-v2')),6)
        specs=candidates('colab-gpu-v3')
        self.assertEqual(len(specs),12)
        self.assertEqual(len({s['id'] for s in specs}),12)
        self.assertEqual({s['depth'] for s in specs if s['kind']=='xgb'},{6,8,10,12})
        self.assertTrue(all(s['quantile_device']=='cpu' for s in specs if s['kind']=='xgb'))

    def test_mean_weight_one_and_reduced_ratio(self):
        counts=np.array([100000,10])
        for mode,ratio in [('balanced',10000),('sqrt',100)]:
            weights=class_weights(counts,mode)
            self.assertAlmostEqual(float(weights@counts/counts.sum()),1.)
            self.assertAlmostEqual(weights[1]/weights[0],ratio)

    def test_fpr_budget_and_zero_detection_rejected(self):
        def result(recall,fpr):
            return {'validation':{'recall':recall,'fpr':fpr,'precision':.1,'confusion':{'tp':1,'fn':5}},
                    'test':{'recall':1.,'fpr':0.}}
        results={'noisy':result(.5,.006),'quiet':result(1/6,.0005),'silent':result(0,0)}
        self.assertEqual(select_model(results,.001,True)['selected_model'],'quiet')
        del results['quiet']
        self.assertIsNone(select_model(results,.001,True)['selected_model'])
