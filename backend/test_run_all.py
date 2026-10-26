"""
Tests for the one-click "run all scans" flow.

Covers /api/scan/all, /api/scan/<id>/status, /api/scan/<id>/stop and
/api/scan/modules, plus the progress-reporting contract the frontend
progress bar depends on.

Run with:  python test_run_all.py
"""

import time
import unittest
from unittest import mock

import server


class RunAllScansTests(unittest.TestCase):
    def setUp(self):
        server.app.config['TESTING'] = True
        self.client = server.app.test_client()
        server.active_scans.clear()
        server.scan_results.clear()
        server.scan_workers.clear()

    def tearDown(self):
        server.active_scans.clear()
        server.scan_results.clear()
        server.scan_workers.clear()

    # ---------- module listing ----------

    def test_modules_endpoint_lists_every_module(self):
        data = self.client.get('/api/scan/modules').get_json()
        self.assertEqual(data['count'], len(data['modules']))
        for expected in ('sqli', 'xss', 'idor', 'lfi', 'cve', 'port'):
            self.assertIn(expected, data['modules'])

    # ---------- validation ----------

    def test_run_all_requires_a_target(self):
        self.assertEqual(
            self.client.post('/api/scan/all', json={}).status_code, 400
        )

    def test_run_all_rejects_invalid_target(self):
        self.assertEqual(
            self.client.post(
                '/api/scan/all', json={'target_url': 'not a url'}
            ).status_code,
            400,
        )

    def test_run_all_rejects_before_launching_anything(self):
        response = self.client.post(
            '/api/scan/all',
            json={'targets': ['https://good.example.com', 'bad target']},
        )
        self.assertEqual(response.status_code, 400)
        # The valid target must not have been started
        self.assertEqual(len(server.active_scans), 0)

    def test_start_scan_rejects_empty_module_list(self):
        response = self.client.post(
            '/api/scan',
            json={'target_url': 'https://example.com', 'modules': []},
        )
        self.assertEqual(response.status_code, 400)

    # ---------- one-click flow (scan body stubbed) ----------

    def test_run_all_expands_to_every_module(self):
        with mock.patch.object(
            server, '_launch_scan', return_value='scan_test'
        ) as launch:
            response = self.client.post(
                '/api/scan/all', json={'target_url': 'https://example.com'}
            )

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'started')
        self.assertEqual(data['module_count'], len(server.ALL_SCAN_MODULES))

        # _launch_scan receives the expanded list, not the "all" alias
        args, _ = launch.call_args
        self.assertNotIn('all', args[1])
        self.assertEqual(sorted(args[1]), sorted(server.ALL_SCAN_MODULES))

    def test_run_all_supports_multiple_targets(self):
        with mock.patch.object(server, '_launch_scan', side_effect=['a', 'b']):
            data = self.client.post(
                '/api/scan/all',
                json={'targets': ['https://one.example.com',
                                  'https://two.example.com']},
            ).get_json()
        self.assertEqual(data['scan_ids'], ['a', 'b'])
        self.assertEqual(len(data['targets']), 2)

    def test_run_all_passes_config_through(self):
        with mock.patch.object(
            server, '_launch_scan', return_value='scan_test'
        ) as launch:
            self.client.post(
                '/api/scan/all',
                json={'target_url': 'https://example.com',
                      'config': {'aggressive_mode': True}},
            )
        self.assertEqual(launch.call_args[0][2], {'aggressive_mode': True})

    def test_scan_ids_are_unique(self):
        with mock.patch.object(server, 'VulnerabilityScanner'), \
             mock.patch.object(server.threading, 'Thread'):
            first = server._launch_scan('https://a.example.com', ['all'])
            second = server._launch_scan('https://b.example.com', ['all'])
        self.assertNotEqual(first, second)

    # ---------- progress + status ----------

    def test_status_reports_live_progress(self):
        server.active_scans['scan_p'] = {
            'status': 'running',
            'progress': 42,
            'current_step': 'Testing SQL Injection...',
            'completed_modules': 5,
            'total_modules': 24,
        }
        data = self.client.get('/api/scan/scan_p/status').get_json()
        self.assertEqual(data['progress'], 42)
        self.assertEqual(data['current_step'], 'Testing SQL Injection...')
        self.assertEqual(data['completed_modules'], 5)
        self.assertEqual(data['total_modules'], 24)

    def test_status_pins_progress_when_finished(self):
        server.active_scans['scan_c'] = {'status': 'completed', 'progress': 37}
        data = self.client.get('/api/scan/scan_c/status').get_json()
        self.assertEqual(data['progress'], 100)

    def test_status_for_unknown_scan(self):
        self.assertEqual(self.client.get('/api/scan/nope/status').status_code, 404)

    # ---------- stop ----------

    def test_stop_requests_cancellation(self):
        scanner = mock.Mock()
        server.active_scans['scan_s'] = {'status': 'running'}
        server.scan_workers['scan_s'] = scanner

        response = self.client.post('/api/scan/scan_s/stop')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['status'], 'stopping')
        scanner.request_cancel.assert_called_once()

    def test_stop_rejects_finished_scan(self):
        server.active_scans['scan_f'] = {'status': 'completed'}
        self.assertEqual(self.client.post('/api/scan/scan_f/stop').status_code, 409)

    def test_stop_rejects_unknown_scan(self):
        self.assertEqual(self.client.post('/api/scan/zzz/stop').status_code, 404)

    # ---------- scan loop behaviour ----------

    @staticmethod
    def _make_scanner(modules, *scanner_map):
        """Build a real VulnerabilityScanner with stubbed scanners."""
        scanner = server.VulnerabilityScanner.__new__(server.VulnerabilityScanner)
        server.VulnerabilityScanner.__init__(
            scanner, 'https://example.com', modules
        )
        return scanner, scanner_map

    @staticmethod
    def _stub(**extra):
        stub = mock.Mock()
        stub.findings = []
        stub.scan_results = []
        stub.scan.return_value = []
        stub.detect.return_value = {}
        stub.test.return_value = {}
        for key, value in extra.items():
            setattr(stub, key, value)
        return stub

    def test_full_scan_runs_and_reports_progress(self):
        stub = self._stub()
        scanner, _ = self._make_scanner(['all'])

        seen = []
        with mock.patch.object(
            server.VulnerabilityScanner, 'build_scanners',
            return_value={'sqli': stub, 'xss': stub, 'port': stub}
        ), mock.patch.object(server.VulnerabilityScanner, 'detect_technologies'):
            server.active_scans['scan_e2e'] = {'status': 'running'}
            scanner.run_full_scan(
                'scan_e2e',
                progress_callback=lambda sid, msg, pct: seen.append((msg, pct)),
            )

        self.assertEqual(server.active_scans['scan_e2e']['status'], 'completed')
        self.assertTrue(seen, 'progress callback was never invoked')
        percents = [p for _, p in seen]
        # Percentages must be monotonic and end at 100
        self.assertEqual(percents, sorted(percents))
        self.assertEqual(percents[-1], 100)
        for mod in scanner.module_status.values():
            self.assertEqual(mod['status'], 'completed')

    def test_cancelled_scan_keeps_partial_results(self):
        stub = self._stub()
        scanner, _ = self._make_scanner(['all'])
        scanner.request_cancel()  # stop before anything runs

        with mock.patch.object(
            server.VulnerabilityScanner, 'build_scanners',
            return_value={'sqli': stub, 'xss': stub}
        ), mock.patch.object(server.VulnerabilityScanner, 'detect_technologies'):
            server.active_scans['scan_c2'] = {'status': 'running'}
            scanner.run_full_scan('scan_c2')

        self.assertEqual(server.active_scans['scan_c2']['status'], 'cancelled')
        result = server.scan_results['scan_c2']
        self.assertTrue(result['cancelled'])
        self.assertEqual(result['findings'], [])

    def test_scan_with_no_matching_modules_completes(self):
        """Regression: this used to hang in 'running' forever."""
        scanner, _ = self._make_scanner([])
        with mock.patch.object(
            server.VulnerabilityScanner, 'build_scanners', return_value={}
        ):
            server.active_scans['scan_empty'] = {'status': 'running'}
            scanner.run_full_scan('scan_empty')

        self.assertEqual(
            server.active_scans['scan_empty']['status'], 'completed'
        )

    def test_failing_module_does_not_abort_scan(self):
        ok = self._stub()
        bad = self._stub()
        bad.scan.side_effect = RuntimeError('boom')

        scanner, _ = self._make_scanner(['all'])
        with mock.patch.object(
            server.VulnerabilityScanner, 'build_scanners',
            return_value={'sqli': bad, 'xss': ok}
        ):
            server.active_scans['scan_f2'] = {'status': 'running'}
            scanner.run_full_scan('scan_f2')

        self.assertEqual(server.active_scans['scan_f2']['status'], 'completed')
        self.assertEqual(scanner.module_status['sqli']['status'], 'failed')
        self.assertEqual(scanner.module_status['xss']['status'], 'completed')

    def test_module_findings_are_collected_and_counted(self):
        finding = {'type': 'SQL Injection', 'severity': 'High', 'url': 'u', 'parameter': 'id'}
        scanner, _ = self._make_scanner(['all'])

        with mock.patch.object(
            server.VulnerabilityScanner, 'build_scanners',
            return_value={'sqli': self._stub()}
        ):
            server.active_scans['scan_r'] = {'status': 'running'}
            # one finding returned, delivered twice to exercise dedup
            scanner.findings = []
            with mock.patch.object(
                server.VulnerabilityScanner, 'is_duplicate_finding',
                side_effect=lambda f: len(scanner.findings) > 0
            ):
                original = server.VulnerabilityScanner.build_scanners

                def build(self):
                    s = original(self)
                    for inst in s.values():
                        inst.scan = mock.Mock(return_value=[finding, finding])
                    return s

                with mock.patch.object(
                    server.VulnerabilityScanner, 'build_scanners', build
                ):
                    scanner.run_full_scan('scan_r')

        self.assertEqual(len(scanner.findings), 1)
        self.assertEqual(scanner.module_status['sqli']['findings'], 2)

    def test_every_scheduled_module_actually_runs(self):
        """Regression: id mismatches silently skipped modules.

        'ports' vs 'port' and 'wordpress' vs 'wp' meant the one-click flow
        scheduled modules that were never built. Assert the scheduled set and
        the executed set match exactly.
        """
        def stub_for(*a, **k):
            s = mock.Mock()
            s.findings = []
            s.scan_results = []
            s.scan.return_value = []
            s.detect_waf.return_value = None
            return s

        names = (
            'SQLiScanner', 'XSSScanner', 'IDORScanner', 'LFIScanner',
            'CommandInjectionScanner', 'FileUploadScanner', 'GraphQLScanner',
            'APIScanner', 'CloudScanner', 'CVEScanner', 'WordPressScanner',
            'GeneralScanner', 'PortScanner', 'FirewallDetector',
            'RateLimitTester', 'OpenRedirectScanner', 'AIScanner',
            'SSRFScanner', 'XXEScanner', 'SSTIScanner', 'DeserializationScanner',
        )
        patches = [mock.patch.object(server, n, side_effect=stub_for) for n in names]
        patches += [
            mock.patch('scanner_modules.fuzzer.Fuzzer', side_effect=stub_for),
            mock.patch('scanner_modules.subdomain_enum.SubdomainEnumerator',
                       side_effect=stub_for),
            mock.patch('scanner_modules.site_mapper.SiteMapper', side_effect=stub_for),
        ]
        for p in patches:
            p.start()
        try:
            data = self.client.post(
                '/api/scan/all', json={'target_url': 'https://example.com'}
            ).get_json()
            scan_id = data['scan_id']
            # Wait for the background worker to finish, with a generous budget
            # so the test does not depend on machine speed.
            deadline = time.time() + 60
            status = {'status': 'running'}
            while time.time() < deadline:
                status = self.client.get(
                    f'/api/scan/{scan_id}/status'
                ).get_json()
                if status['status'] != 'running':
                    break
                time.sleep(0.05)
            result = self.client.get(
                f'/api/scan/{scan_id}/results'
            ).get_json()
        finally:
            for p in patches:
                p.stop()
            # Drop the finished scan so it cannot leak into other tests
            server.active_scans.pop(scan_id, None)
            server.scan_results.pop(scan_id, None)

        scheduled = set(data['modules'])
        executed = set(result['module_status'])
        self.assertEqual(len(scheduled), len(server.ALL_SCAN_MODULES))
        self.assertEqual(
            scheduled - executed, set(), 'modules were scheduled but never ran')
        self.assertEqual(status['status'], 'completed')
        self.assertEqual(status['progress'], 100)


if __name__ == '__main__':
    unittest.main(verbosity=2)