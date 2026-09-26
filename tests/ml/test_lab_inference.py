"""Inference-only tests: no estimator fit or dataset preparation jobs."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import numpy as np

from zetty_uba.lab.core import Detector, Journal, canonical, validate


class FixedModel:
    def __init__(self, value=2., fail=False):self.value=value;self.fail=fail
    def score(self, values):
        if self.fail:raise RuntimeError('fixture failure')
        return np.full(len(values), self.value)


def observation():
    return {'schema_version':'zetty-lab-observation/1','environment':'public-replay',
        'observation_id':'a'*64,'source':'fixture','feature_version':'fixture-v1',
        'features':['a','b'],'values':[1.,2.],'target_key':'b'*64,'occurred_at':'2026-09-27T00:00:00Z'}


def detector(value=2., fail=False):
    d=Detector.__new__(Detector);d.model_id='fixture';d.threshold=1.
    d.revision='c'*64;d.manifest_sha256='d'*64
    d.bundle={'model':FixedModel(value,fail),'features':['a','b'],'source':'fixture','feature_version':'fixture-v1'}
    return d


class LabInference(unittest.TestCase):
    def test_strict_contract_and_missing_values(self):
        validate(observation())
        invalid=[]
        for changes in ({'values':[1,None]},{'values':[1,float('nan')]},{'values':[True,2]},
                        {'values':[1,float('inf')]},{'features':['a','a']},
                        {'environment':'local-secure'},{'occurred_at':'2026-09-27'},
                        {'label':1},{'target_key':'untrusted-user'}):
            value=observation();value.update(changes);invalid.append(value)
        for value in invalid:
            with self.assertRaises(ValueError):validate(value)

    def test_threshold_tie_and_nonprobability_score(self):
        self.assertFalse(detector(1.).detect(observation())['is_anomaly'])
        result=detector(2.).detect(observation())
        self.assertTrue(result['is_anomaly']);self.assertEqual(result['anomaly_score'],2.)
        self.assertEqual(result['policy'],'REVIEW_ONLY')

    def test_mismatch_and_model_failure_are_not_normal(self):
        value=observation();value['features'].reverse()
        for result in (detector().detect(value),detector(fail=True).detect(observation()),
                       detector(float('nan')).detect(observation())):
            self.assertNotEqual(result['status'],'EVALUATED')
            self.assertIsNone(result['anomaly_score']);self.assertIsNone(result['is_anomaly'])

    def test_replay_restart_and_same_id_conflict(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'results.sqlite';j=Journal(path);d=detector();raw=canonical(observation())
            j.process('delivery1',raw,d);j.db.close();j=Journal(path)
            j.process('delivery1',raw,d);j.process('delivery2',raw,d)
            self.assertEqual(j.summary(),{'detections':1,'receipts':{'EVALUATED':2}})
            value=observation();value['values'][0]=99
            self.assertEqual(j.process('delivery3',canonical(value),d),'ID_CONFLICT')
            self.assertEqual(j.summary()['detections'],1)
            with self.assertRaisesRegex(ValueError,'delivery_content_changed'):
                j.process('delivery1',canonical(value),d)
            j.db.close()

    def test_model_revision_separates_results(self):
        j=Journal(':memory:');d=detector();raw=canonical(observation())
        j.process('d1',raw,d);d.revision='e'*64;j.process('d2',raw,d)
        self.assertEqual(j.summary()['detections'],2)

    def test_invalid_input_quarantined_without_raw_payload(self):
        j=Journal(':memory:')
        self.assertEqual(j.process('d1','not-json',detector()),'INVALID_INPUT')
        self.assertEqual(j.summary()['detections'],0)
        self.assertNotIn('not-json',str(j.db.execute('SELECT * FROM receipts').fetchall()))

    def test_storage_failure_does_not_claim_success(self):
        j=Journal(':memory:');j.db.close()
        with self.assertRaises(Exception):j.process('delivery',canonical(observation()),detector())

    def test_bad_manifest_rejected_before_deserialization(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp);(path/'study.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'manifest_checksum_mismatch'):Detector(path,'0'*64)
