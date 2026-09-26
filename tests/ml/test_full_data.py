from collections import Counter
import tempfile
from pathlib import Path
import unittest
import numpy as np
from zetty_uba.study.data import History, NumericSink, emit_group, open_data
from zetty_uba.datasets.rba import parse, from_rows, NAMES


def row(user,second,country='NO'):
    return {'User ID':user,'Login Timestamp':f'2020-02-03T00:00:{second:02}',
            'Country':country,'IP Address':'public-fixture','Device Type':'desktop',
            'Browser Name and Version':'browser','Is Account Takeover':'False','Is Attack IP':'False'}

class FullPreparation(unittest.TestCase):
    def test_exact_history_across_disk_eviction_and_equal_time(self):
        rows=[row('a',0),row('a',0),row('b',1),row('a',2,'DE'),row('b',3),row('a',4)]
        expected=from_rows(rows)
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp)/'data';sink=NumericSink(directory,NAMES,batch_size=2)
            history=History(directory/'history.sqlite',capacity=1)
            pending=[];previous=None;labels=Counter()
            for raw in rows:
                record=parse(raw)
                if previous is not None and record[1]>previous:emit_group(pending,history,sink,labels)
                pending.append(record);previous=record[1]
            emit_group(pending,history,sink,labels)
            history.close();history.close()
            sink.finish({'source':'fixture'})
            arrays,meta=open_data(directory)
            np.testing.assert_allclose(arrays['x'],expected.x,rtol=1e-6)
            np.testing.assert_array_equal(arrays['times'],expected.times)
            self.assertEqual(meta['rows'],len(rows))
            self.assertEqual(labels,{'0':len(rows)})

    def test_sink_rejects_non_finite_and_preserves_existing_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp)/'data';sink=NumericSink(directory,('x',))
            with self.assertRaisesRegex(ValueError,'invalid_numeric_feature'):
                sink.append([np.inf],0,'0'*64,0)
            sink.close()
            with self.assertRaises(FileExistsError):NumericSink(directory,('x',))
