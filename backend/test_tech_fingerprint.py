"""
Tests for the technology fingerprinting module.

Covers header, cookie and body signal extraction, the confidence model,
database detection, version capture and false-positive resistance.

Run with:  python test_tech_fingerprint.py
"""

import unittest
from unittest import mock

from scanner_modules.tech_fingerprint import TechFingerprint


def make_response(text='', status_code=200, headers=None, cookies=None):
    response = mock.Mock()
    response.text = text
    response.status_code = status_code
    response.headers = headers if headers is not None else {}
    response.cookies = cookies if cookies is not None else []
    return response


def cookie(name):
    c = mock.Mock()
    c.name = name
    return c


class HeaderTests(unittest.TestCase):
    def setUp(self):
        self.session = mock.Mock()
        self.tf = TechFingerprint('https://example.com', self.session)

    def test_detects_server_from_server_header(self):
        self.tf.analyze_headers({'Server': 'nginx/1.24.0'})
        names = [i['name'] for i in self.tf.architecture['servers']]
        self.assertIn('Nginx', names)

    def test_captures_server_version(self):
        self.tf.analyze_headers({'Server': 'Apache/2.4.57 (Ubuntu)'})
        item = next(i for i in self.tf.architecture['servers']
                    if i['name'] == 'Apache')
        self.assertEqual(item['version'], '2.4.57')

    def test_detects_language_from_x_powered_by(self):
        self.tf.analyze_headers({'X-Powered-By': 'PHP/8.2.1'})
        names = [i['name'] for i in self.tf.architecture['languages']]
        self.assertIn('PHP', names)

    def test_detects_iis(self):
        self.tf.analyze_headers({'Server': 'Microsoft-IIS/10.0'})
        names = [i['name'] for i in self.tf.architecture['servers']]
        self.assertIn('Microsoft IIS', names)

    def test_detects_cdn(self):
        self.tf.analyze_headers({'Server': 'cloudflare', 'CF-RAY': 'abc-DFW'})
        names = [i['name'] for i in self.tf.architecture['infrastructure']]
        self.assertIn('Cloudflare', names)

    def test_detects_cms_from_x_generator(self):
        self.tf.analyze_headers({'X-Generator': 'Drupal 10 (drupal.org)'})
        names = [i['name'] for i in self.tf.architecture['cms']]
        self.assertIn('Drupal', names)
        self.assertEqual(self.tf.evidence['generator'], 'Drupal 10 (drupal.org)')

    def test_no_server_header_still_scans_others(self):
        self.tf.analyze_headers({'CF-RAY': 'x-1-DFW'})
        names = [i['name'] for i in self.tf.architecture['infrastructure']]
        self.assertIn('Cloudflare', names)

    def test_empty_headers_are_safe(self):
        self.tf.analyze_headers({})
        self.tf.analyze_headers(None)


class CookieTests(unittest.TestCase):
    def setUp(self):
        self.session = mock.Mock()
        self.tf = TechFingerprint('https://example.com', self.session)

    def test_php_session_cookie_detects_php(self):
        self.tf.analyze_cookies([cookie('PHPSESSID')])
        names = [i['name'] for i in self.tf.architecture['languages']]
        self.assertIn('PHP', names)

    def test_jsessionid_detects_java(self):
        self.tf.analyze_cookies([cookie('JSESSIONID')])
        names = [i['name'] for i in self.tf.architecture['languages']]
        self.assertIn('Java', names)

    def test_laravel_cookie_detects_framework(self):
        self.tf.analyze_cookies([cookie('laravel_session')])
        names = [i['name'] for i in self.tf.architecture['frameworks']]
        self.assertIn('Laravel', names)

    def test_cfduid_detects_cloudflare(self):
        self.tf.analyze_cookies([cookie('__cfduid')])
        names = [i['name'] for i in self.tf.architecture['infrastructure']]
        self.assertIn('Cloudflare', names)

    def test_cookies_are_recorded_as_evidence(self):
        self.tf.analyze_cookies([cookie('PHPSESSID')])
        self.assertIn('PHPSESSID', self.tf.evidence['cookies'])


class BodyTests(unittest.TestCase):
    def setUp(self):
        self.session = mock.Mock()
        self.tf = TechFingerprint('https://example.com', self.session)

    def test_detects_wordpress_from_generator_meta(self):
        self.tf.analyze_body(
            '<meta name="generator" content="WordPress 6.4.1">')
        item = next(i for i in self.tf.architecture['cms']
                    if i['name'] == 'WordPress')
        self.assertEqual(item['version'], '6.4.1')

    def test_detects_database_from_error_text(self):
        self.tf.analyze_body(
            'Fatal error: mysqli_real_connect() in index.php on line 4')
        names = [i['name'] for i in self.tf.architecture['databases']]
        self.assertIn('MySQL', names)

    def test_detects_postgres_from_error(self):
        self.tf.analyze_body('PG::UnableToSend: could not connect')
        names = [i['name'] for i in self.tf.architecture['databases']]
        self.assertIn('PostgreSQL', names)

    def test_detects_mongodb_from_driver_error(self):
        self.tf.analyze_body('MongoError: connection timed out')
        names = [i['name'] for i in self.tf.architecture['databases']]
        self.assertIn('MongoDB', names)

    def test_database_evidence_helper(self):
        self.assertFalse(self.tf.has_database_evidence())
        self.tf.analyze_body('MongoError: boom')
        self.assertTrue(self.tf.has_database_evidence())

    def test_detects_frontend_library(self):
        self.tf.analyze_body('<script src="/js/jquery-3.6.0.min.js"></script>')
        names = [i['name'] for i in self.tf.architecture['frontend']]
        self.assertIn('jQuery', names)

    def test_detects_cms_deep_in_page(self):
        """Regression: matching used to truncate at 20 chars and miss this."""
        body = ('<html><head><title>Site</title></head><body>' + 'x' * 500 +
                '<meta name="generator" content="WordPress 6.4.1"></body></html>')
        self.tf.analyze_body(body)
        names = [i['name'] for i in self.tf.architecture['cms']]
        self.assertIn('WordPress', names)

    def test_go_is_not_matched_inside_googletagmanager(self):
        """Regression: 'Go' matched inside 'googletagmanager'."""
        self.tf.analyze_body(
            '<script src="https://www.googletagmanager.com/gtag/js"></script>')
        names = [i['name'] for i in self.tf.architecture['languages']]
        self.assertNotIn('Go', names)

    def test_doctype_alone_is_not_xml(self):
        """Regression: any HTML doctype was reported as XML."""
        self.tf.analyze_body('<!DOCTYPE html><html><body>hi</body></html>')
        names = [i['name'] for i in self.tf.architecture['languages']]
        self.assertNotIn('XML', names)

    def test_error_page_finding_lands_in_frameworks(self):
        self.tf.analyze_body('<h1>Routing Error</h1>')
        names = [i['name'] for i in self.tf.architecture['frameworks']]
        self.assertIn('Ruby on Rails', names)

    def test_graphql_is_reported_under_apis(self):
        self.tf.analyze_body('{"query":"{__typename}"}')
        names = [i['name'] for i in self.tf.architecture['apis']]
        self.assertIn('GraphQL API', names)


class ConfidenceTests(unittest.TestCase):
    def setUp(self):
        self.session = mock.Mock()
        self.tf = TechFingerprint('https://example.com', self.session)

    def test_duplicate_detections_are_merged(self):
        self.tf.analyze_headers({'Server': 'nginx/1.24.0'})
        before = len(self.tf.architecture['servers'])
        self.tf.analyze_headers({'Server': 'nginx/1.25.1'})
        self.assertEqual(len(self.tf.architecture['servers']), before)

    def test_high_confidence_is_not_downgraded(self):
        self.tf.analyze_headers({'Server': 'nginx/1.24.0'})
        item = self.tf.architecture['servers'][0]
        self.assertEqual(item['confidence'], 'high')
        # A later weak signal must not downgrade it
        self.tf._add('servers', 'Nginx', confidence='low')
        self.assertEqual(
            next(i for i in self.tf.architecture['servers']
                 if i['name'] == 'Nginx')['confidence'],
            'high',
        )

    def test_evidence_is_accumulated(self):
        self.tf._add('servers', 'Nginx', evidence='one')
        self.tf._add('servers', 'nginx', evidence='two')
        item = self.tf.architecture['servers'][0]
        self.assertIn('one', item['evidence'])
        self.assertIn('two', item['evidence'])

    def test_technologies_is_flat_and_unique(self):
        self.tf.analyze_headers({'Server': 'nginx/1.24.0'})
        self.tf.analyze_headers({'X-Powered-By': 'PHP/8.2'})
        names = self.tf.technologies
        self.assertEqual(len(names), len(set(names)))
        self.assertIn('Nginx', names)
        self.assertIn('PHP', names)

    def test_summary_is_human_readable(self):
        self.tf.analyze_headers({'Server': 'nginx/1.24.0',
                                 'X-Powered-By': 'PHP/8.2.1'})
        summary = self.tf.summary()
        self.assertIn('Server:', summary)
        self.assertIn('PHP', summary)

    def test_summary_when_nothing_detected(self):
        self.assertEqual(self.tf.summary(), 'No technologies identified')


class ScanTests(unittest.TestCase):
    def test_scan_reports_architecture_and_database(self):
        session = mock.Mock()
        session.get.return_value = make_response(
            '<meta name="generator" content="WordPress 6.4.1">'
            '<script src="/js/jquery.min.js"></script>'
            'MySQL 8.0',
            headers={'Server': 'nginx/1.24.0', 'X-Powered-By': 'PHP/8.2.1'},
            cookies=[cookie('PHPSESSID')],
        )
        tf = TechFingerprint('https://example.com', session)
        findings = tf.scan()

        self.assertTrue(tf.architecture['servers'])
        self.assertTrue(tf.architecture['databases'])
        titles = ' '.join(f['title'] for f in findings)
        self.assertIn('architecture', titles.lower())
        self.assertIn('database', titles.lower())

    def test_scan_flags_version_disclosure(self):
        session = mock.Mock()
        session.get.return_value = make_response(
            '<html></html>', headers={'Server': 'nginx/1.24.0'})
        tf = TechFingerprint('https://example.com', session)
        findings = tf.scan()
        self.assertTrue(
            any('version disclosed' in f['title'] for f in findings))

    def test_scan_handles_no_technologies(self):
        session = mock.Mock()
        session.get.return_value = make_response('<html></html>', headers={})
        tf = TechFingerprint('https://example.com', session)
        findings = tf.scan()
        self.assertTrue(findings)
        self.assertIn('No technology', findings[0]['title'])

    def test_scan_survives_network_error(self):
        import requests
        session = mock.Mock()
        session.get.side_effect = requests.RequestException('down')
        tf = TechFingerprint('https://example.com', session)
        findings = tf.scan()
        self.assertIsInstance(findings, list)

    def test_error_page_probe_is_used(self):
        home = make_response('<html>home</html>', headers={})

        def fake_get(url, **kwargs):
            if 'missing_404' in url:
                return make_response(
                    'Whitelabel Error Page', status_code=500, headers={})
            return home

        session = mock.Mock()
        session.get.side_effect = fake_get
        tf = TechFingerprint('https://example.com', session)
        tf.scan()
        names = [i['name'] for i in tf.architecture['frameworks']]
        self.assertIn('Spring Boot', names)


if __name__ == '__main__':
    unittest.main(verbosity=2)