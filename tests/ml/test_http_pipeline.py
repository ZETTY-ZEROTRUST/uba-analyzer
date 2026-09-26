"""File pipeline tests with fixed score fixture; no training."""
import copy
import json
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
from zetty_log.__main__ import produce
from zetty_log.http import normalize
from zetty_uba.datasets.online_shop import NAMES,window_features
from zetty_uba.lab.core import Detector
from zetty_uba.lab.http_file import detect,pipeline


class Model:
 def score(self,x):return np.full(len(x),2.)


def model():
 d=Detector.__new__(Detector);d.model_id='fixture';d.threshold=1.;d.revision='c'*64;d.manifest_sha256='d'*64
 d.bundle={'model':Model(),'source':'online-shop-18895701','features':list(NAMES),'feature_version':'public-http-5min-v1-f32-v2'}
 return d


def event(i,stamp=None,size=100):
 return normalize({'request_id':f'{i:032x}','time':stamp or f'2026-09-27T00:01:{i:02d}Z',
   'remote_addr':'192.0.2.1','user_agent':'fixture','method':'GET','uri':'/items','status':200,'body_bytes':size},bytes(32),'fixture-v1')


def capture(complete=True):
 return {'capture_start':'2026-09-27T00:00:00Z','capture_end':'2026-09-27T00:05:00Z',
 'complete':complete,'key_version':'fixture-v1','environment':'local-lab'}


class HTTPPipeline(unittest.TestCase):
 def test_feature_golden(self):
  rows=[('u',0,'GET','a',200,100),('u',10,'GET','a',404,300)]
  expected=[math.log(3),math.log(2),.5,math.log(401),math.log(201),math.log(301),.5,0,math.log(2),math.log(11),0]
  np.testing.assert_allclose(window_features(rows),expected,rtol=1e-14)
 def test_order_independent_result_with_explicit_transfer(self):
  first=detect([event(1),event(2)],capture(),model())
  second=detect([event(2),event(1)],capture(),model())
  self.assertEqual(first,second);r=first[0]
  self.assertTrue(r['is_anomaly']);self.assertEqual(r['environment'],'local-lab')
  self.assertEqual(r['target_type'],'observed-client');self.assertEqual(r['data_origin'],'local-http-transfer')
 def test_missing_bytes_incomplete_capture_and_low_activity(self):
  for events,meta,status in [([event(1),event(2,size=None)],capture(),'INCOMPLETE_WINDOW'),
      ([event(1),event(2)],capture(False),'INCOMPLETE_WINDOW'),([event(1)],capture(),'INSUFFICIENT_DATA')]:
   r=detect(events,meta,model())[0]
   self.assertEqual(r['status'],status);self.assertIsNone(r['anomaly_score']);self.assertIsNone(r['is_anomaly'])
 def test_partial_boundary_not_complete_by_clock(self):
  meta=capture();meta['capture_start']='2026-09-27T00:00:30Z'
  self.assertEqual(detect([event(1),event(2)],meta,model())[0]['status'],'INCOMPLETE_WINDOW')
 def test_wrong_model_source_rejected(self):
  d=model();d.bundle['source']='rba-6782156'
  with self.assertRaisesRegex(ValueError,'http_model_contract_mismatch'):detect([event(1),event(2)],capture(),d)
 def test_durable_idempotent_output_and_checksum_rejection(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);src=root/'raw.jsonl'
   rows=[{'request_id':f'{i:032x}','time':f'2026-09-27T00:01:{i:02d}Z','remote_addr':'192.0.2.1',
          'user_agent':'fixture','method':'GET','uri':'/items','status':200,'body_bytes':100} for i in (1,2)]
   src.write_text(''.join(json.dumps(r)+'\n' for r in rows))
   produce(src,root/'capture',bytes(32),'fixture-v1','2026-09-27T00:00:00Z','2026-09-27T00:05:00Z',True)
   with patch('zetty_uba.lab.http_file.Detector',return_value=model()):
    for _ in range(2):
     result=pipeline(root/'capture',root/'model','d'*64,'fixture',root/'out')
     self.assertEqual(result['persisted_detections'],1)
    with (root/'capture/events.jsonl').open('a') as stream:stream.write('{}\n')
    with self.assertRaisesRegex(ValueError,'capture_checksum_mismatch'):
     pipeline(root/'capture',root/'model','d'*64,'fixture',root/'out')
