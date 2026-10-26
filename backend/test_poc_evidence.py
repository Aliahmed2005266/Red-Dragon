"""
Tests for proof-of-concept evidence collection.

Covers the recording session, PoC building, exchange matching, secret
redaction, memory bounds, and that evidence never breaks a scan.

Run with:  python test_poc_evidence.py
"""

import unittest
from unittest import mock

import requests

from scanner_modules.poc_evidence import (
    RecordingSession, attach_poc, fill_missing_poc, build_poc, summarise,
    _redact_headers, _excerpt, _build_curl, MAX_EXCHANGES,
)


def fake_response(body='', status=200, headers=None):
    r = mock.Mock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    return r


def exchange(url, body='', status=200, method='GET', headers=None, req_headers=None):
    return {
        'method': method, 'url': url,
        'request_headers': req_headers or {},
        'request_body': None,
        'status': status,
        'response_headers': headers or {},
        'body': body, 'body_length': len(body),
    }


class RedactionTests(unittest.TestCase):
    def test_credentials_are_redacted(self):
        out = _redact_headers({
            'Authorization': 'Bearer sk-SECRET',
            'Cookie': 'session=SECRET',
            'X-Api-Key': 'SECRET',
            'Accept': 'text/html',
        })
        self.assertEqual(out['Authorization'], '<redacted>')
        self.assertEqual(out['Cookie'], '<redacted>')
        self.assertEqual(out['X-Api-Key'], '<redacted>')
        self.assertEqual(out['Accept'], 'text/html')

    def test_no_secret_survives(self):
        out = _redact_headers({'Authorization': 'sk-SECRET'})
        self.assertNotIn('SECRET', str(out))

    def test_curl_keeps_secret_shape_but_not_value(self):
        curl = _build_curl('GET', 'https://t.com', {'Authorization': '<redacted>'}, None)
        self.assertNotIn('sk-', curl)
        self.assertIn('your-value-here', curl)


class ExcerptTests(unittest.TestCase):
    def test_excerpt_is_bounded(self):
        self.assertLess(len(_excerpt('a' * 100000)), 2100)

    def test_excerpt_centres_on_marker(self):
        text = 'x' * 5000 + 'NEEDLE' + 'y' * 5000
        out = _excerpt(text, 'NEEDLE')
        self.assertIn('NEEDLE', out)
        self.assertLess(len(out), 600)

    def test_excerpt_without_marker_truncates(self):
        self.assertTrue(_excerpt('a' * 10000).endswith('...'))

    def test_empty_excerpt(self):
        self.assertEqual(_excerpt(''), '')


class RecordingSessionTests(unittest.TestCase):
    def setUp(self):
        self.session = RecordingSession()

    def _stub(self, body='hello', status=200):
        return mock.patch.object(
            requests.Session, 'request',
            return_value=fake_response(body, status))

    def test_records_exchange(self):
        with self._stub('the body'):
            self.session.get('https://t.com/a', timeout=5)
        ex = self.session.exchanges
        self.assertEqual(len(ex), 1)
        self.assertEqual(ex[0]['method'], 'GET')
        self.assertEqual(ex[0]['url'], 'https://t.com/a')
        self.assertEqual(ex[0]['status'], 200)
        self.assertEqual(ex[0]['body'], 'the body')

    def test_records_post_body(self):
        with self._stub():
            self.session.post('https://t.com/a', data={'x': '1'})
        self.assertEqual(self.session.exchanges[0]['request_body'], {'x': '1'})

    def test_records_failed_request_then_reraises(self):
        with mock.patch.object(requests.Session, 'request',
                               side_effect=requests.RequestException('down')):
            with self.assertRaises(requests.RequestException):
                self.session.get('https://t.com/a')
        self.assertEqual(len(self.session.exchanges), 1)
        self.assertIsNone(self.session.exchanges[0]['status'])

    def test_buffer_is_bounded(self):
        s = RecordingSession(max_exchanges=10)
        with self._stub('x' * 100):
            for i in range(50):
                s.get(f'https://t.com/{i}')
        self.assertLessEqual(len(s.exchanges), 10)
        # The most recent are kept
        self.assertIn('/49', s.exchanges[-1]['url'])

    def test_bodies_are_truncated_in_buffer(self):
        with self._stub('a' * 100000):
            self.session.get('https://t.com/a')
        ex = self.session.exchanges[0]
        self.assertLess(len(ex['body']), 100000)
        # The true length is still reported
        self.assertEqual(ex['body_length'], 100000)

    def test_sensitive_headers_redacted_at_record_time(self):
        with self._stub():
            self.session.get('https://t.com/a',
                             headers={'Authorization': 'Bearer sk-SECRET'})
        self.assertNotIn('SECRET', str(self.session.exchanges[0]))

    def test_clear(self):
        with self._stub():
            self.session.get('https://t.com/a')
        self.session.clear()
        self.assertEqual(self.session.exchanges, [])


class PocBuildTests(unittest.TestCase):
    def test_no_exchange_keeps_location(self):
        poc = build_poc({'url': 'https://t.com/a?x=1', 'parameter': 'x'}, [])
        self.assertFalse(poc['available'])
        self.assertIn('reason', poc)
        self.assertEqual(poc['location']['url'], 'https://t.com/a?x=1')
        self.assertEqual(poc['location']['parameter'], 'x')
        self.assertEqual(poc['location']['query'], {'x': '1'})

    def test_matches_on_payload(self):
        ex = exchange('https://t.com/a?id=<script>', body='x')
        poc = build_poc({'url': 'https://t.com/a', 'payload': '<script>'}, [ex])
        self.assertTrue(poc['available'])
        self.assertEqual(poc['match'], 'exact-payload')

    def test_matches_on_exact_url(self):
        ex = exchange('https://t.com/a?x=1', body='ok')
        poc = build_poc({'url': 'https://t.com/a?x=1'}, [ex])
        self.assertEqual(poc['match'], 'exact-url')

    def test_falls_back_to_same_endpoint(self):
        ex = exchange('https://t.com/a?other=2', body='ok')
        poc = build_poc({'url': 'https://t.com/a?x=1'}, [ex])
        self.assertEqual(poc['match'], 'same-endpoint')

    def test_reflected_payload_is_the_marker(self):
        body = '<html>REFLECTED: <script>alert(1)</script></html>'
        ex = exchange('https://t.com/a?q=<script>alert(1)</script>', body=body)
        poc = build_poc({'url': 'https://t.com/a', 'payload': '<script>alert(1)</script>'}, [ex])
        marker = poc['marker']
        self.assertEqual(marker['type'], 'reflected-payload')
        self.assertEqual(marker['value'], '<script>alert(1)</script>')
        self.assertEqual(marker['offset'], body.find('<script>alert(1)</script>'))
        self.assertIn('REFLECTED', poc['response']['excerpt'])

    def test_pattern_evidence_is_used_as_marker(self):
        body = 'You have an error in your SQL syntax'
        ex = exchange('https://t.com/a?id=1', body=body)
        poc = build_poc({
            'url': 'https://t.com/a', 'parameter': 'id',
            'evidence': 'Error pattern: You have an error in your SQL syntax',
        }, [ex])
        self.assertEqual(poc['marker']['type'], 'pattern-match')
        self.assertIn('SQL syntax', poc['marker']['value'])

    def test_scanner_evidence_without_body_match(self):
        ex = exchange('https://t.com/a', body='unrelated')
        poc = build_poc({
            'url': 'https://t.com/a', 'evidence': 'Timing: 5.1s',
        }, [ex])
        self.assertEqual(poc['marker']['type'], 'scanner-evidence')
        self.assertIn('5.1s', poc['marker']['value'])

    def test_baseline_is_found(self):
        base = exchange('https://t.com/a', body='clean page')
        test = exchange('https://t.com/a?q=x', body='clean page with input')
        poc = build_poc({'url': 'https://t.com/a', 'payload': 'x'}, [base, test])
        self.assertIsNotNone(poc['baseline'])
        self.assertEqual(poc['baseline']['url'], 'https://t.com/a')

    def test_curl_command_is_produced(self):
        ex = exchange('https://t.com/a?q=1', body='ok')
        poc = build_poc({'url': 'https://t.com/a', 'payload': '1'}, [ex])
        self.assertIn('curl -i -X GET', poc['request']['curl'])
        self.assertIn('https://t.com/a?q=1', poc['request']['curl'])

    def test_location_method_comes_from_exchange(self):
        ex = exchange('https://t.com/a', body='ok', method='POST')
        poc = build_poc({'url': 'https://t.com/a'}, [ex])
        self.assertEqual(poc['location']['method'], 'POST')


class AttachTests(unittest.TestCase):
    def test_attach_adds_poc_to_every_finding(self):
        ex = exchange('https://t.com/a?x=1', body='ok')
        findings = [{'url': 'https://t.com/a?x=1'}, {'url': 'https://t.com/b'}]
        attach_poc(findings, [ex])
        self.assertIn('poc', findings[0])
        self.assertIn('poc', findings[1])

    def test_fill_missing_does_not_overwrite_good_evidence(self):
        good = {'url': 'https://t.com/a',
                'poc': {'available': True, 'keep': 'original'}}
        missing = {'url': 'https://t.com/a'}
        # First pass finds nothing; the finding is marked as lacking evidence
        attach_poc([missing], [])
        self.assertFalse(missing['poc']['available'])
        # The second pass tops up the gap but leaves the good evidence alone
        fill_missing_poc([good, missing], [exchange('https://t.com/a', body='ok')])
        self.assertEqual(good['poc']['keep'], 'original')
        self.assertTrue(missing['poc']['available'])

    def test_non_dict_findings_are_skipped(self):
        attach_poc(['not a dict', None], [])
        # Must not raise

    def test_empty_input(self):
        self.assertEqual(attach_poc([], []), [])

    def test_summarise_counts(self):
        result = summarise([{'available': True}, {'available': False}, {}])
        self.assertEqual(result['total'], 3)
        self.assertEqual(result['with_evidence'], 1)
        self.assertEqual(result['without_evidence'], 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)