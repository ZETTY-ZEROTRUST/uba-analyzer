import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
import pyarrow as pa
import pyarrow.parquet as pq
from zetty_uba.datasets.rbd24 import load, NAMES

class RbdAudit(unittest.TestCase):
    def test_all_conflicting_rows_quarantined(self):
        columns = {name: [1., 2., 3., 3., 4.] for name in NAMES}
        start = datetime(2022, 10, 14)
        columns.update(timestamp=[start, start, start+timedelta(hours=1), start+timedelta(hours=1), start+timedelta(hours=2)],
                       user_id=['u']*5, entity=['desktop']*5, label=[0]*5)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'source.parquet'
            pq.write_table(pa.table(columns), path)
            data=load(path)
            self.assertEqual(len(data.times), 2)
            self.assertEqual(data.audit['quarantined_rows'], 2)
            self.assertEqual(data.audit['quarantined_conflicting_groups'], 1)
            self.assertEqual(data.audit['deduplicated_windows'], 1)
            self.assertEqual(data.x[:,0].tolist(), [3.,4.])
