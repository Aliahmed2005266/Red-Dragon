"""
Tests for finding deduplication.

Covers vulnerability-class canonicalisation, URL normalisation, identity
matching, merge behaviour (nothing lost), severity ordering, and the
defensive handling of malformed input.

Run with:  python test_finding_dedupe.py
"""

import unittest

from scanner_modules.finding_dedupe import (
    dedupe_findings, sort_findings, identity, canonical_class,
    normalize_url, severity_rank, _loose_key,
)


def finding(**kw):
    base = {
        'type': 'SQL Injection',
        'severity': 'High',
        'title': 'SQLi detected',
        'description': 'desc',
        'url': 'https://t.com/a?id=1',
        'remediation': 'fix it',
    }
    base.update(kw)
    return base


class ClassTests(unittest.TestCase):
    def test_aliases_collapse(self):
        variants = ['SQLi', 'SQL Injection', 'sql injection (sqli)',
                    'SQL Injection (SQLi)']
        classes = {canonical_class({'type': v}) for v in variants}
        self.assertEqual(classes, {'SQL Injection'})

    def test_xss_variants(self):
        for v in ['XSS', 'Cross-Site Scripting (XSS)', 'reflected xss']:
            self.assertEqual(
                canonical_class({'type': v}), 'Cross-Site Scripting (XSS)')

    def test_unknown_type_is_preserved(self):
        self.assertEqual(canonical_class({'type': 'Weird Thing'}), 'Weird Thing')

    def test_missing_type(self):
        self.assertEqual(canonical_class({}), 'Unknown')


class UrlTests(unittest.TestCase):
    def test_default_ports_collapse(self):
        self.assertEqual(normalize_url('http://t.com:80/a'),
                         normalize_url('http://t.com/a'))

    def test_trailing_slash_collapsed(self):
        self.assertEqual(normalize_url('https://t.com/a/'),
                         normalize_url('https://t.com/a'))

    def test_parameter_values_stripped(self):
        self.assertEqual(normalize_url('https://t.com/a?id=1'),
                         normalize_url('https://t.com/a?id=999'))

    def test_query_can_be_dropped(self):
        self.assertEqual(normalize_url('https://t.com/a?id=1', include_query=False),
                         'https://t.com/a')

    def test_parameter_names_kept_when_query_included(self):
        self.assertNotEqual(normalize_url('https://t.com/a?x=1'),
                            normalize_url('https://t.com/a?y=1'))

    def test_empty_url(self):
        self.assertEqual(normalize_url(''), '')
        self.assertEqual(normalize_url(None), '')


class IdentityTests(unittest.TestCase):
    def test_different_payload_same_issue_is_same_identity(self):
        a = identity(finding(url='https://t.com/a?id=<script>x</script>', parameter='id'))
        b = identity(finding(url='https://t.com/a?id=<script>y</script>', parameter='id'))
        self.assertEqual(a, b)

    def test_different_parameter_is_different(self):
        a = identity(finding(parameter='id'))
        b = identity(finding(parameter='page'))
        self.assertNotEqual(a, b)

    def test_different_endpoint_is_different(self):
        a = identity(finding(url='https://t.com/a'))
        b = identity(finding(url='https://t.com/b'))
        self.assertNotEqual(a, b)

    def test_poc_request_url_is_preferred(self):
        f = finding(url='https://t.com/a?id=1', parameter='id')
        f['poc'] = {'request': {'url': 'https://t.com/a?id=<payload>'}}
        self.assertIn('t.com/a', identity(f)[1])

    def test_non_dict_identity(self):
        self.assertEqual(identity('nope'), ('Invalid', '', ''))


class LooseKeyTests(unittest.TestCase):
    def test_same_payload_same_endpoint_collapses(self):
        a = _loose_key(finding(url='https://t.com/a', payload='P'))
        b = _loose_key(finding(url='https://t.com/a?q=1', payload='P'))
        self.assertEqual(a, b)

    def test_no_payload_cannot_collapse(self):
        self.assertIsNone(_loose_key(finding(url='https://t.com/a')))

    def test_different_payload_does_not_collapse(self):
        a = _loose_key(finding(url='https://t.com/a', payload='P1'))
        b = _loose_key(finding(url='https://t.com/a', payload='P2'))
        self.assertNotEqual(a, b)


class DedupeTests(unittest.TestCase):
    def test_identical_findings_collapse(self):
        findings = [finding(), finding(), finding()]
        unique, stats = dedupe_findings(findings)
        self.assertEqual(len(unique), 1)
        self.assertEqual(stats['merged'], 2)

    def test_distinct_findings_are_kept(self):
        findings = [finding(parameter='id'), finding(parameter='page')]
        unique, stats = dedupe_findings(findings)
        self.assertEqual(len(unique), 2)
        self.assertEqual(stats['merged'], 0)

    def test_same_issue_different_payloads_merge(self):
        findings = [
            finding(url='https://t.com/a?id=1', payload='A'),
            finding(url='https://t.com/a?id=2', payload='B'),
        ]
        unique, stats = dedupe_findings(findings)
        self.assertEqual(len(unique), 1)
        self.assertEqual(set(unique[0]['payloads']), {'A', 'B'})

    def test_highest_severity_wins(self):
        findings = [
            finding(severity='Low'),
            finding(severity='Critical'),
            finding(severity='Medium'),
        ]
        unique, _ = dedupe_findings(findings)
        self.assertEqual(unique[0]['severity'], 'Critical')

    def test_longer_description_wins(self):
        findings = [
            finding(description='short'),
            finding(description='a much longer and more useful description'),
        ]
        unique, _ = dedupe_findings(findings)
        self.assertEqual(unique[0]['description'],
                         'a much longer and more useful description')

    def test_best_poc_is_kept(self):
        weak = finding()
        weak['poc'] = {'available': True, 'marker': {'type': 'response'}}
        strong = finding()
        strong['poc'] = {'available': True,
                         'marker': {'type': 'reflected-payload'},
                         'request': {'curl': 'curl x'},
                         'response': {'excerpt': 'body'}}
        unique, _ = dedupe_findings([weak, strong])
        self.assertEqual(unique[0]['poc']['marker']['type'], 'reflected-payload')

    def test_poc_kept_when_duplicate_has_none(self):
        with_poc = finding()
        with_poc['poc'] = {'available': True, 'marker': {'type': 'reflected-payload'}}
        unique, _ = dedupe_findings([with_poc, finding()])
        self.assertTrue(unique[0]['poc']['available'])

    def test_alternative_titles_preserved(self):
        findings = [finding(title='First title'), finding(title='Second title')]
        unique, _ = dedupe_findings(findings)
        self.assertEqual(unique[0]['title'], 'First title')
        self.assertIn('Second title', unique[0]['variants'])

    def test_evidence_strings_collected(self):
        findings = [finding(evidence='one'), finding(evidence='two')]
        unique, _ = dedupe_findings(findings)
        self.assertEqual(set(unique[0]['evidence_list']), {'one', 'two'})

    def test_modules_collected(self):
        findings = [finding(module='xss'), finding(module='web')]
        unique, _ = dedupe_findings(findings)
        self.assertEqual(set(unique[0]['modules']), {'xss', 'web'})

    def test_merged_count_recorded(self):
        unique, _ = dedupe_findings([finding(), finding(), finding()])
        self.assertEqual(unique[0]['merged_count'], 2)

    def test_originals_not_mutated(self):
        original = finding(title='keep me')
        snapshot = dict(original)
        dedupe_findings([original, finding()])
        self.assertEqual(original, snapshot)

    def test_empty_bookkeeping_is_removed(self):
        unique, _ = dedupe_findings([finding()])
        for field in ('payloads', 'evidence_list', 'variants', 'modules'):
            self.assertNotIn(field, unique[0])

    def test_non_dict_entries_skipped(self):
        unique, stats = dedupe_findings([finding(), 'bad', None])
        self.assertEqual(len(unique), 1)
        self.assertEqual(stats['invalid_skipped'], 2)

    def test_empty_input(self):
        unique, stats = dedupe_findings([])
        self.assertEqual(unique, [])
        self.assertEqual(stats['unique'], 0)

    def test_realistic_xss_variants_merge(self):
        payloads = ["<script>alert('XSS')</script>", '<img src=x onerror=alert(1)>']
        findings = [
            finding(type='Cross-Site Scripting (XSS)', parameter='q',
                    url=f'https://t.com/s?q={p}', payload=p)
            for p in payloads
        ]
        unique, stats = dedupe_findings(findings)
        self.assertEqual(len(unique), 1)
        self.assertEqual(len(unique[0]['payloads']), 2)

    def test_different_vuln_classes_do_not_merge(self):
        findings = [finding(type='SQL Injection'), finding(type='Cross-Site Scripting (XSS)')]
        unique, _ = dedupe_findings(findings)
        self.assertEqual(len(unique), 2)

    def test_stats_add_up(self):
        findings = [finding()] * 5 + [finding(parameter='other')]
        unique, stats = dedupe_findings(findings)
        self.assertEqual(stats['original'], 6)
        self.assertEqual(stats['unique'], len(unique))
        self.assertEqual(stats['merged'] + stats['unique'] + stats['invalid_skipped'],
                         stats['original'])


class SortTests(unittest.TestCase):
    def test_severity_order(self):
        findings = [finding(severity='Info'), finding(severity='Critical'),
                    finding(severity='Low'), finding(severity='High')]
        ordered = [f['severity'] for f in sort_findings(findings)]
        self.assertEqual(ordered, ['Critical', 'High', 'Low', 'Info'])

    def test_severity_rank(self):
        self.assertLess(severity_rank('Critical'), severity_rank('High'))
        self.assertLess(severity_rank('High'), severity_rank('Info'))
        # Unknown sorts last
        self.assertGreater(severity_rank('Bogus'), severity_rank('Info'))

    def test_sort_is_stable_for_same_severity(self):
        findings = [finding(type='B'), finding(type='A')]
        ordered = [f['type'] for f in sort_findings(findings)]
        self.assertEqual(ordered, ['A', 'B'])



class ReportRenderTests(unittest.TestCase):
    """The HTML report must escape everything merged in from the target."""

    @classmethod
    def setUpClass(cls):
        import server
        cls.server = server

    def test_no_block_for_plain_finding(self):
        out = self.server._render_merged_html({'title': 'x'})
        self.assertEqual(out, '')

    def test_handles_none_fields(self):
        out = self.server._render_merged_html(
            {'payloads': None, 'merged_count': 0})
        self.assertEqual(out, '')

    def test_bad_merged_count_does_not_raise(self):
        out = self.server._render_merged_html({'merged_count': 'x'})
        self.assertIsInstance(out, str)

    def test_payload_is_escaped(self):
        out = self.server._render_merged_html(
            {'payloads': ['<script>alert(1)</script>']})
        self.assertNotIn('<script>', out)
        self.assertIn('&lt;script&gt;', out)

    def test_cannot_break_out_of_details(self):
        out = self.server._render_merged_html(
            {'variants': ['</details><script>bad()</script>']})
        self.assertNotIn('</details><script>', out)

    def test_evidence_is_escaped(self):
        out = self.server._render_merged_html(
            {'evidence_list': ['<img src=x onerror=alert(1)>']})
        self.assertNotIn('<img', out)

    def test_modules_escaped(self):
        out = self.server._render_merged_html({'modules': ['<b>x</b>']})
        self.assertNotIn('<b>x</b>', out)

    def test_full_report_renders_merged_findings(self):
        result = {
            'target': 'http://t.com',
            'scan_date': '2026-01-01',
            'statistics': {'critical': 1, 'high': 0, 'medium': 0,
                           'low': 0, 'info': 0, 'total_findings': 1},
            'findings': [{
                'title': 'SQLi', 'type': 'SQL Injection', 'severity': 'High',
                'description': 'd', 'url': 'http://t.com/a', 'remediation': 'r',
                'merged_count': 2, 'payloads': ['<script>x</script>'],
                'modules': ['sqli'],
            }],
        }
        out = self.server.generate_html_report(result)
        self.assertIn('Corroborating detail', out)
        self.assertNotIn('<script>x</script>', out)

    def test_report_renders_every_finding(self):
        """Sorting is the scan state's job, not the report's, so the report
        must simply render every finding it is handed."""
        result = {
            'target': 'http://t.com', 'scan_date': '2026-01-01',
            'statistics': {'critical': 1, 'high': 1, 'medium': 0, 'low': 0,
                           'info': 0, 'total_findings': 2},
            'findings': [
                {'title': 'low one', 'type': 'A', 'severity': 'Low',
                 'description': 'd', 'url': '', 'remediation': 'r'},
                {'title': 'crit one', 'type': 'B', 'severity': 'Critical',
                 'description': 'd', 'url': '', 'remediation': 'r'},
            ],
        }
        out = self.server.generate_html_report(result)
        self.assertIn('low one', out)
        self.assertIn('crit one', out)

    def test_scan_state_sorts_by_severity(self):
        """The scanner itself orders results so the worst issues surface first."""
        from server import VulnerabilityScanner
        scanner = VulnerabilityScanner('http://t.com')
        scanner.findings = [
            {'type': 'A', 'severity': 'Info', 'url': 'http://t.com/a'},
            {'type': 'B', 'severity': 'Critical', 'url': 'http://t.com/b'},
        ]
        scanner.dedupe_findings()
        self.assertEqual([f['severity'] for f in scanner.findings],
                         ['Critical', 'Info'])
        self.assertEqual(scanner.dedupe_stats['unique'], 2)

if __name__ == '__main__':
    unittest.main(verbosity=2)