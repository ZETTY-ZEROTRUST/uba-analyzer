import tempfile
import unittest
from pathlib import Path
import numpy as np
from zetty_uba.datasets.common import Observations, verify_file
from zetty_uba.datasets.online_shop import parse_line, load
from zetty_uba.training.split import chronological
from zetty_uba.training.benchmark import metrics, threshold_from_calibration, run

class Contracts(unittest.TestCase):
    def test_time_group_and_embargo(self):
        times = np.repeat(np.arange(1000)*300, 2)[::-1]
        parts, metadata = chronological(times, embargo_seconds=600)
        sets = [set(times[p]) for p in parts.values()]
        self.assertFalse(sets[0] & sets[1] or sets[1] & sets[2])
        self.assertGreaterEqual(min(sets[1])-metadata['first_boundary'], 600)
        self.assertGreaterEqual(min(sets[2])-metadata['second_boundary'], 600)

    def test_unknown_labels_never_fpr(self):
        value = metrics(np.array([0., 2.]), 1., np.array([-1, -1]))
        self.assertEqual(value['flag_rate'], .5)
        self.assertIsNone(value['fpr'])
        self.assertIsNone(value['confusion'])

    def test_ties_strict_threshold(self):
        scores = np.ones(100)
        threshold = threshold_from_calibration(scores)
        self.assertEqual(metrics(scores, threshold, np.zeros(100))['flagged'], 0)
        with self.assertRaises(ValueError):
            threshold_from_calibration(np.full(100, np.nan))

    def test_missing_bytes_not_zero(self):
        line = 'client - - [08/Dec/2025:01:00:00 +0000] "GET /a?q=secret HTTP/1.1" 200 0 "-" "agent"'
        row = parse_line(line)
        self.assertEqual(row[3], '/a')
        self.assertEqual(row[5], 0)
        with self.assertRaises(ValueError):
            parse_line(line.replace('200 0', '200 -'))
        with self.assertRaises(ValueError):
            parse_line('x'*65537)

    def test_boundary_windows_excluded_repeats_retained(self):
        def row(time):
            return f'client - - [08/Dec/2025:00:{time} +0000] "GET /a HTTP/1.1" 200 10 "-" "agent"\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'input.log'
            path.write_text(row('01:00') + row('05:01')*2 + row('11:00'))
            data = load(path)
            self.assertEqual(len(data.times), 1)
            self.assertEqual(data.audit['identical_requests_retained'], 1)
            self.assertEqual(data.audit['excluded_windows']['capture_boundary'], 2)
            with self.assertRaises(ValueError):
                load(path, max_rows=2)

    def test_checksum_rejects_before_parse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'data'
            path.write_bytes(b'bad')
            with self.assertRaises(ValueError):
                verify_file(path, size=3, md5='0'*32)

    def test_real_estimators_and_manifest(self):
        rng = np.random.default_rng(42)
        x = rng.normal(size=(1000, 3))
        labels = np.zeros(1000, dtype=int)
        labels[::5] = 1
        x[::5] += 4
        data = Observations('fixture', 'v1', ('a','b','c'), x,
                            np.arange(1000)*300, np.array(['entity']*1000), labels, {}).validate()
        with tempfile.TemporaryDirectory() as directory:
            result = run(data, Path(directory)/'run', source_manifest={'fixture': True},
                         max_train=200, embargo_seconds=300, supervised=True)
            self.assertEqual(result['status'], 'COMPLETED')
            self.assertEqual(len(result['models']), 4)
            self.assertLessEqual(result['reference_train_rows'], 200)
            for model in result['models'].values():
                self.assertEqual(model['status'], 'EVALUATED')
                self.assertTrue((Path(directory)/'run'/model['artifact']['file']).is_file())
                self.assertEqual(model['test']['labeled_rows'], model['test']['rows'])
            with self.assertRaises(ValueError):
                run(data, Path(directory)/'run', source_manifest={})

if __name__ == '__main__':
    unittest.main()
