"""
Tests for the parameter discovery module.

Covers URL/path parsing, form and JavaScript extraction, name validation,
classification, and the differential probe that decides whether a parameter is
actually processed by the server.

Run with:  python test_param_discovery.py
"""

import unittest
from unittest import mock

import requests

from scanner_modules.param_discovery import ParamDiscovery


def make_response(text='', status_code=200):
    response = mock.Mock()
    response.text = text
    response.status_code = status_code
    response.headers = {}
    return response


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.session = mock.Mock()
        self.session.get.return_value = make_response('<html></html>')
        self.discovery = ParamDiscovery('https://example.com', self.session)
        self.discovery.probe_limit = 0

    def test_extracts_query_params_from_target_url(self):
        found = self.discovery.extract_from_url(
            'https://example.com/search?q=test&page=2')
        self.assertEqual(sorted(e['name'] for e in found), ['page', 'q'])

    def test_records_param_value_and_location(self):
        self.discovery.extract_from_url('https://example.com/?id=42')
        entry = self.discovery.parameters['id']
        self.assertEqual(entry['values'], ['42'])
        self.assertIn('query', entry['locations'])

    def test_blank_values_are_kept(self):
        self.discovery.extract_from_url('https://example.com/?debug=')
        self.assertIn('debug', self.discovery.parameters)

    def test_extracts_rest_path_params(self):
        found = self.discovery.extract_path_params(
            'https://example.com/user/123/post/456')
        self.assertIn('id', {e['name'] for e in found})

    def test_extracts_named_path_param(self):
        found = self.discovery.extract_path_params('https://example.com/user-99')
        self.assertEqual(found[0]['name'], 'user')
        self.assertEqual(found[0]['values'], ['99'])

    def test_extracts_uuid_path_segment(self):
        found = self.discovery.extract_path_params(
            'https://example.com/550e8400-e29b-41d4-a716-446655440000')
        self.assertEqual(found[0]['name'], 'uuid')

    def test_merges_repeat_sightings(self):
        self.discovery.extract_from_url('https://example.com/?id=1')
        self.discovery.extract_from_url('https://example.com/?id=2')
        entry = self.discovery.parameters['id']
        self.assertEqual(entry['values'], ['1', '2'])
        self.assertEqual(len(self.discovery.parameters), 1)

    def test_classifies_by_keyword(self):
        cases = {'page': 'pagination', 'id': 'id', 'q': 'search',
                 'redirect': 'redirect', 'file': 'file', 'api_key': 'auth',
                 'sort': 'sort', 'zzzz': 'unknown'}
        for name, expected in cases.items():
            self.assertEqual(self.discovery._classify(name), expected, name)

    def test_classification_matches_prefixes_and_suffixes(self):
        self.assertEqual(self.discovery._classify('page_size'), 'pagination')
        self.assertEqual(self.discovery._classify('user_id'), 'id')

    def test_rejects_invalid_names(self):
        for bad in ('', '  ', '1abc', 'a' * 100, 'has space', 'class', None):
            self.assertFalse(self.discovery._is_valid_name(bad), repr(bad))

    def test_accepts_valid_names(self):
        for good in ('id', 'apiKey', 'user_id', 'items[0]', 'q.x'):
            self.assertTrue(self.discovery._is_valid_name(good), good)

    def test_form_fields_become_params(self):
        html = ('<form method="POST" action="/login">'
                '<input name="username" value="bob">'
                '<input name="password" type="password">'
                '<input type="submit" value="Go"></form>')
        self.discovery.extract_from_html(html, 'https://example.com/')
        self.assertIn('username', self.discovery.parameters)
        self.assertIn('password', self.discovery.parameters)
        self.assertNotIn('Go', self.discovery.parameters)
        self.assertEqual(
            self.discovery.parameters['username']['locations'], ['body'])

    def test_get_form_fields_are_query_params(self):
        html = '<form action="/s"><input name="q"></form>'
        self.discovery.extract_from_html(html, 'https://example.com/')
        self.assertEqual(self.discovery.parameters['q']['locations'], ['query'])

    def test_link_params_are_extracted(self):
        self.discovery.extract_from_html(
            '<a href="/item?id=42">x</a>', 'https://example.com/')
        self.assertIn('id', self.discovery.parameters)
        self.assertIn('link', self.discovery.parameters['id']['sources'])

    def test_external_links_are_ignored(self):
        self.discovery.extract_from_html(
            '<a href="https://evil.com/x?other=1">x</a>', 'https://example.com/')
        self.assertNotIn('other', self.discovery.parameters)

    def test_extracts_params_from_js(self):
        js = 'fetch("/api?apiKey=abc&limit=10"); formData.append("csrf", "v");'
        self.discovery.extract_from_js(js)
        self.assertIn('apiKey', self.discovery.parameters)
        self.assertIn('limit', self.discovery.parameters)
        self.assertIn('csrf', self.discovery.parameters)

    def test_inline_script_is_mined(self):
        self.discovery.extract_from_html(
            '<script>var u = "/x?inlineParam=1";</script>', 'https://example.com/')
        self.assertIn('inlineParam', self.discovery.parameters)

    def test_script_src_is_recorded_for_later(self):
        self.discovery.extract_from_html(
            '<script src="/app.js"></script>', 'https://example.com/')
        self.assertIn('https://example.com/app.js', self.discovery._script_urls)


class ProbeTests(unittest.TestCase):
    """Differential analysis: does the server actually use the parameter?"""

    def _discovery(self):
        session = mock.Mock()
        return ParamDiscovery('https://example.com/', session), session

    def test_canary_echo_marks_parameter_live(self):
        discovery, session = self._discovery()

        def fake_get(url, **kwargs):
            if discovery.CANARY in url:
                return make_response('x' * 100 + discovery.CANARY, 200)
            return make_response('x' * 100, 200)

        session.get.side_effect = fake_get
        discovery.record('realparam', 'query')
        discovery.probe_parameters({'status': 200, 'length': 100})
        discovery._flush()

        entry = discovery.parameters['realparam']
        self.assertTrue(entry['live'])
        self.assertEqual(entry['live_confidence'], 'high')

    def test_no_response_change_marks_parameter_dead(self):
        discovery, session = self._discovery()
        session.get.return_value = make_response('y' * 500, 200)
        discovery.record('fakeparam', 'query')
        discovery.probe_parameters({'status': 200, 'length': 500})

        entry = discovery.parameters['fakeparam']
        self.assertFalse(entry['live'])
        self.assertEqual(entry['live_confidence'], 'low')

    def test_size_change_marks_parameter_live(self):
        discovery, session = self._discovery()
        session.get.return_value = make_response('z' * 5000, 200)
        discovery.record('bigparam', 'query')
        discovery.probe_parameters({'status': 200, 'length': 200})

        self.assertTrue(discovery.parameters['bigparam']['live'])
        self.assertEqual(
            discovery.parameters['bigparam']['live_confidence'], 'medium')

    def test_status_change_marks_parameter_live(self):
        discovery, session = self._discovery()
        session.get.return_value = make_response('z' * 200, 500)
        discovery.record('errparam', 'query')
        discovery.probe_parameters({'status': 200, 'length': 200})
        self.assertTrue(discovery.parameters['errparam']['live'])

    def test_probe_limit_is_respected(self):
        discovery, session = self._discovery()
        session.get.return_value = make_response('a' * 100, 200)
        discovery.probe_limit = 3
        for i in range(10):
            discovery.record('p%d' % i, 'query')

        discovery.probe_parameters({'status': 200, 'length': 100})
        self.assertLessEqual(session.get.call_count, 3)

    def test_probe_url_preserves_existing_query(self):
        discovery, _ = self._discovery()
        url = discovery._build_probe_url('newparam')
        self.assertIn('newparam=', url)
        self.assertIn(discovery.CANARY, url)

    def test_probe_without_baseline_is_a_noop(self):
        discovery, session = self._discovery()
        discovery.record('x', 'query')
        discovery.probe_parameters(None)
        session.get.assert_not_called()


class ScanTests(unittest.TestCase):
    def _run_scan(self, html='', status=200):
        session = mock.Mock()
        session.get.return_value = make_response(html, status)
        discovery = ParamDiscovery('https://example.com/', session)
        discovery.max_pages = 1
        discovery.probe_limit = 0
        return discovery, discovery.scan()

    def test_scan_returns_findings(self):
        _, findings = self._run_scan('<a href="/?id=1">x</a>')
        self.assertTrue(findings)
        self.assertIn('parameters', findings[0])

    def test_scan_reports_sensitive_params(self):
        _, findings = self._run_scan('<a href="/?api_key=1&password=2">x</a>')
        titles = ' '.join(f['title'] for f in findings)
        self.assertIn('sensitive', titles.lower())

    def test_scan_survives_network_failure(self):
        session = mock.Mock()
        session.get.side_effect = requests.RequestException('boom')
        discovery = ParamDiscovery('https://example.com/', session)
        findings = discovery.scan()
        self.assertIsInstance(findings, list)

    def test_wordlist_used_when_nothing_found(self):
        discovery, _ = self._run_scan('<html><body>no links</body></html>')
        self.assertTrue(discovery.parameters)
        self.assertIn('query', discovery.parameters)

    def test_discovered_parameters_populated(self):
        discovery, _ = self._run_scan('<a href="/?id=1">x</a>')
        self.assertTrue(discovery.discovered_parameters)
        self.assertEqual(discovery.discovered_parameters[0]['name'], 'id')


if __name__ == '__main__':
    unittest.main(verbosity=2)
