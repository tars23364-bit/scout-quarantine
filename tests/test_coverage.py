import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


scout = module('scoutlib', 'lib/scoutlib.py')
extract = module('coverage_metadata', 'docker/coverage.py')
merge = module('merge', 'lib/merge-extractions.py')
validator = module('validator', 'lib/validate-schema.py')


def entry(path, start, end):
    return dict(source_path=path, byte_start=start, byte_end=end, content='x',
                lines_read='1-200', total_lines=1)


def fixture():
    return dict(schema_version='1.0', strategy='structured', timestamp='test',
                file_tree=[], extraction_canary='test', file_count=3, total_size_bytes=60,
                suspicious_indicators={k: [] for k in validator.REQUIRED_SUSPICIOUS},
                text_inventory={'a': 10, 'b': 20, 'c': 30},
                file_contents={'a': entry('a', 0, 10), 'b': entry('b', 0, 5)})


def report():
    r = {k: '' for k in scout.REPORT_SCHEMA['required']}
    r.update(verdict='CLEAN', risk_assessment='LOW', recommendation='SAFE_TO_USE',
             dependencies=[], network_calls=[], injection_attempts=[], red_flags=[])
    return r


class CoverageTests(unittest.TestCase):
    def test_full_truncated_unread(self):
        c = scout.coverage_for(fixture(), [])
        self.assertEqual((c['text_files'], c['files_read'], c['files_full'], c['files_truncated']), (3, 2, 1, 1))
        self.assertEqual((c['bytes_read'], c['bytes_total'], c['bytes_percent']), (15, 60, 25))
        self.assertTrue(c['coverage_partial'])

    def test_overlap_deduplicated_and_complementary_views(self):
        m = fixture()
        m['file_contents'].update({'b [alt-view]': entry('b', 3, 20), 'a [alt-view]': entry('a', 0, 10)})
        c = scout.coverage_for(m, [])
        self.assertEqual((c['files_read'], c['files_full'], c['bytes_read']), (2, 2, 30))

    def test_disjoint_ranges_leave_gap(self):
        m = fixture()
        m['file_contents']['b [alt-view]'] = entry('b', 10, 20)
        c = scout.coverage_for(m, [])
        self.assertEqual((c['files_full'], c['files_truncated'], c['bytes_read']), (1, 1, 25))

    def test_budget_omission(self):
        c = scout.coverage_for(fixture(), ['a'])
        self.assertEqual((c['files_read'], c['files_omitted_for_budget'], c['bytes_read']), (1, 1, 5))

    def test_budget_omitted_alternate_is_not_an_omitted_file(self):
        m = fixture()
        m['file_contents']['a [alt-view]'] = entry('a', 0, 10)
        c = scout.coverage_for(m, ['a [alt-view]'])
        self.assertEqual((c['files_omitted_for_budget'], c['views_omitted_for_budget']), (0, 1))
        self.assertTrue(c['coverage_partial'])

    def test_full_coverage(self):
        m = fixture()
        m['file_contents'] = {p: entry(p, 0, n) for p, n in m['text_inventory'].items()}
        self.assertFalse(scout.coverage_for(m, [])['coverage_partial'])

    def test_legacy_unknown_is_partial(self):
        m = fixture()
        del m['text_inventory']
        c = scout.coverage_for(m, [])
        self.assertIsNone(c['text_files'])
        self.assertIsNone(c['bytes_percent'])
        self.assertTrue(c['coverage_partial'])

    def test_invalid_range_never_counts(self):
        m = fixture()
        m['file_contents']['a']['byte_end'] = 100
        c = scout.coverage_for(m, [])
        self.assertEqual(c['bytes_read'], 5)
        self.assertFalse(c['measurement_complete'])

    def test_empty_window_does_not_count_file(self):
        m = fixture()
        m['file_contents']['a'] = entry('a', 10, 10)
        self.assertEqual(scout.coverage_for(m, [])['files_read'], 1)

    def test_zero_denominator(self):
        c = scout.coverage_for(dict(text_inventory={}, file_contents={}), [])
        self.assertEqual(c['bytes_percent'], 0)
        self.assertFalse(c['coverage_partial'])

    def test_render_scoped_without_changing_enum(self):
        c = scout.coverage_for(fixture(), [])
        r = report()
        md = scout.render_md(r, dict(target='example', model='test', mission_id='test', files_seen=2, files_omitted=0, coverage=c))
        for text in ['COVERAGE:', '## SCOPE', 'covers the 2 files read (1 full, 1 truncated) of 3 text files, 25% of bytes; files not read are not covered', 'safe for an AI agent to READ/adopt', 'says nothing about whether the software is correct or safe to RUN; what the code controls is out of scope', 'SAFE_TO_USE (sampled, see SCOPE)']:
            self.assertIn(text, md)
        self.assertEqual(r['recommendation'], 'SAFE_TO_USE')

    def test_full_render_has_no_sampled_suffix(self):
        m = fixture()
        m['file_contents'] = {p: entry(p, 0, n) for p, n in m['text_inventory'].items()}
        md = scout.render_md(report(), dict(target='example', model='test', mission_id='test', files_seen=3, files_omitted=0, coverage=scout.coverage_for(m, [])))
        self.assertNotIn('(sampled, see SCOPE)', md)
        self.assertIn('100% of bytes', md)

    def test_unknown_render_does_not_claim_complete(self):
        md = scout.render_md(report(), dict(target='example', model='test', mission_id='test', files_seen=0, files_omitted=0, coverage=scout.coverage_for({}, [])))
        self.assertIn('unknown percentage of bytes', md)
        self.assertIn('SAFE_TO_USE (sampled, see SCOPE)', md)

    def test_canary_does_not_inflate_reads(self):
        m = fixture()
        m['file_contents']['.scout-verify'] = dict(content='canary')
        c = scout.coverage_for(m, [])
        self.assertEqual(c['files_read'], 2)
        self.assertTrue(c['measurement_complete'])

    def test_merge_retains_identity(self):
        a, b = fixture(), fixture()
        b['file_contents']['b'] = entry('b', 5, 20)
        m = merge.merge(copy.deepcopy(a), copy.deepcopy(b))
        self.assertEqual(scout.coverage_for(m, [])['bytes_read'], 30)
        b['text_inventory']['a'] = 11
        self.assertFalse(merge.consistency_check(a, b)[0])

    def test_extraction_census_and_ranges(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = ('é\n' * 210).encode()
            (root / 'sample.txt').write_bytes(raw)
            (root / '.scout-verify').write_text('canary\n')
            (root / '.git').mkdir()
            (root / '.git' / 'ignore').write_text('ignore\n')
            (root / 'link').symlink_to(root / 'sample.txt')
            (root / 'binary').write_bytes(b'\x00\xff')
            for mode, lo, hi in [('1-200', 0, 600), ('tail-200', 30, 630), ('150-350', 447, 630)]:
                data = dict(file_contents={'sample.txt': dict(lines_read=mode, content=raw[lo:hi].decode())})
                result = extract.annotate(data, root)
                self.assertEqual(result['text_inventory'], {'sample.txt': 630})
                self.assertEqual((data['file_contents']['sample.txt']['byte_start'], data['file_contents']['sample.txt']['byte_end']), (lo, hi))

    def test_unterminated_last_line_and_empty_mid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'a.txt').write_text('hello')
            for mode, content, span in [('1-200', 'hello\n', (0, 5)), ('150-350', '\n', (5, 5))]:
                data = dict(file_contents={'a.txt': dict(lines_read=mode, content=content)})
                extract.annotate(data, root)
                e = data['file_contents']['a.txt']
                self.assertEqual((e['byte_start'], e['byte_end']), span)

    def test_schema_accepts_annotated_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'extraction.json'
            p.write_text(json.dumps(fixture()))
            self.assertEqual(validator.validate(str(p)), (True, []))

    def test_analyze_overrides_model_coverage_and_uses_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp)
            (z / 'merged-extraction.json').write_text(json.dumps(fixture()))
            (z / 'mission.md').write_text('Target: example\n')
            r = report()
            r.update(coverage_partial=False, coverage={'bytes_percent': 100})
            response = json.dumps(dict(message=dict(content=json.dumps(r)))).encode()
            import io
            with patch.object(scout.urllib.request, 'urlopen', return_value=io.BytesIO(response)), patch.object(scout, 'CONTENT_BUDGET_CHARS', 0):
                scout.cmd_analyze(str(z), 'test', str(ROOT / 'lib/scout-prompt.md'))
            saved = json.loads((z / 'report/scout-report.json').read_text())
            self.assertTrue(saved['coverage_partial'])
            self.assertEqual(saved['coverage']['files_read'], 0)
            self.assertEqual(saved['coverage'], saved['_scout']['coverage'])
            for field in scout.REPORT_SCHEMA['required']:
                self.assertIn(field, saved)
            for field in ('verdict', 'risk_assessment', 'recommendation'):
                self.assertIn(saved[field], scout.REPORT_SCHEMA['properties'][field]['enum'])


if __name__ == '__main__':
    unittest.main()
