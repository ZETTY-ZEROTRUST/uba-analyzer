import tempfile
import unittest
from pathlib import Path
import zipfile
import numpy as np
from zetty_uba.datasets.rba import from_rows, load, parse


def row(second, country='NO', outcome='False', attack='False', ato='False'):
    return {'User ID': 'fixture-user', 'Login Timestamp': f'2020-02-02T00:{second//60:02}:{second%60:02}',
            'Country': country, 'IP Address': 'fixture-ip', 'Device Type': 'desktop',
            'Browser Name and Version': 'fixture-browser', 'Is Attack IP': attack,
            'Is Account Takeover': ato, 'Login Successful': outcome}

class RbaCausality(unittest.TestCase):
    def test_equal_time_only_earlier_history(self):
        data = from_rows([row(0), row(0), row(1)], max_rows=100)
        self.assertTrue(np.array_equal(data.x[0], data.x[1]))
        self.assertEqual(data.x[0,1], 1)
        self.assertAlmostEqual(data.x[2,0], np.log1p(2))
        self.assertEqual(data.x[2,1], 0)
        self.assertEqual(data.x[2,3], 0)
        self.assertEqual(data.x[2,4], 1)

    def test_outcomes_and_future_do_not_change_features(self):
        a = from_rows([row(0), row(1), row(2)])
        b = from_rows([row(0,outcome='True',ato='True'), row(1,attack='True'), row(2,country='DE')])
        self.assertTrue(np.array_equal(a.x[:2],b.x[:2]))
        self.assertEqual(b.labels.tolist(), [1,-1,0])

    def test_out_of_order_rejected(self):
        with self.assertRaisesRegex(ValueError, 'source_not_chronological'):
            from_rows([row(1),row(0)])

    def test_cutoff_excludes_last_group(self):
        data = from_rows([row(i//2) for i in range(101)], max_rows=100)
        self.assertEqual(len(data.times), 98)
        self.assertEqual(data.audit['cutoff_group_rows_excluded'],2)

    def test_missing_context_rejected_not_zero(self):
        invalid = row(1)
        invalid['Device Type'] = ''
        data = from_rows([row(0),invalid,row(2)])
        self.assertEqual(data.audit['rejected_rows'], {'missing_required_value':1})
        self.assertEqual(len(data.times),2)

    def test_archive_path_and_line_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'bad.zip'
            with zipfile.ZipFile(path,'w') as archive:
                archive.writestr('../data.csv','x')
            with self.assertRaisesRegex(ValueError, 'unsafe_member_path'):
                load(path)
            with zipfile.ZipFile(path,'w') as archive:
                archive.writestr('data.csv','x'*65537)
            with self.assertRaisesRegex(ValueError, 'decompression_budget_exceeded'):
                load(path)

class LabelBoundary(unittest.TestCase):
    def test_all_unknown_task_rows_never_become_normal(self):
        from zetty_uba.training.benchmark import run
        data = from_rows([row(i, attack='True') for i in range(1000)])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'insufficient_reference_rows'):
                run(data, Path(directory)/'run', source_manifest={}, embargo_seconds=0)
            self.assertFalse((Path(directory)/'run').exists())
