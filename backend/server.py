"""
Red Dragon - Advanced Web Vulnerability Scanner Backend
Author: aegis cyber works
Version: 1.0.0
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import json
import time
import os
from datetime import datetime, timedelta
import threading
import queue
import requests
from urllib.parse import urlparse, urljoin
import re
import sys
import socket
import uuid

# Scanner modules
from scanner_modules.sql_injection import SQLiScanner
from scanner_modules.xss_scanner import XSSScanner
from scanner_modules.idor_scanner import IDORScanner
from scanner_modules.lfi_scanner import LFIScanner
from scanner_modules.file_upload_scanner import FileUploadScanner
from scanner_modules.command_injection import CommandInjectionScanner
from scanner_modules.graphql_scanner import GraphQLScanner
from scanner_modules.api_scanner import APIScanner
from scanner_modules.cloud_scanner import CloudScanner
from scanner_modules.cve_scanner import CVEScanner
from scanner_modules.wordpress_scanner import WordPressScanner
from scanner_modules.general_scanner import GeneralScanner
from scanner_modules.port_scanner import PortScanner
from scanner_modules.firewall_detector import FirewallDetector
from scanner_modules.rate_limit_tester import RateLimitTester
from scanner_modules.open_redirect_scanner import OpenRedirectScanner
from scanner_modules.encoding_handler import EncodingHandler, AdvancedEncoder
from scanner_modules.ai_scanner import AIScanner
from scanner_modules.ai_agent import ai_agent, normalize_model_name
from scanner_modules.ssrf_scanner import SSRFScanner
from scanner_modules.xxe_scanner import XXEScanner
from scanner_modules.ssti_scanner import SSTIScanner
from scanner_modules.deserialization_scanner import DeserializationScanner
from scanner_modules.param_discovery import ParamDiscovery
from scanner_modules.tech_fingerprint import TechFingerprint
from scanner_modules.ai_security_agent import SecurityAgent
from scanner_modules.poc_evidence import (
    RecordingSession, attach_poc, fill_missing_poc, summarise as summarise_poc,
)
from scanner_modules.finding_dedupe import (
    dedupe_findings as dedupe,
    sort_findings,
    identity as finding_identity,
)


app = Flask(__name__)
CORS(app)

# Global variables for scan management
active_scans = {}
scan_results = {}
scan_queue = queue.Queue()

# Scanner instances kept alive so a running scan can be cancelled on request
scan_workers = {}


class ScanCancelled(Exception):
    """Raised internally when a scan is stopped via the /stop endpoint."""


# Every scanner module the tool knows about, in execution order.
# The "run all" one-click flow expands to exactly this list. Keys match the
# internal scanner ids used by build_scanners(), so the list maps 1:1.
ALL_SCAN_MODULES = [
    'sqli', 'xss', 'idor', 'lfi', 'cmd', 'upload', 'redirect', 'ssrf',
    'xxe', 'ssti', 'deser', 'graphql', 'api', 'cloud', 'cve', 'wp',
    'ai', 'general', 'port', 'firewall', 'rate', 'fuzz', 'subdomain', 'sitemap',
    'params', 'fingerprint',
]

class VulnerabilityScanner:
    def __init__(self, target_url, scan_modules=None, record_evidence=True):
        self.target_url = target_url.rstrip('/')
        self.is_ip = False
        self.domain = ""
        
        # Check if target is IP or URL
        try:
            # Try to parse as URL first
            parsed = urlparse(target_url)
            if parsed.scheme and parsed.netloc:
                self.domain = parsed.netloc
            else:
                # Treat as IP
                self.is_ip = True
                self.domain = target_url
                self.target_url = f"http://{target_url}"
        except:
            self.is_ip = True
            self.domain = target_url
            self.target_url = f"http://{target_url}"
        
        # Extract IP from domain if needed
        if not self.is_ip:
            try:
                self.ip_address = socket.gethostbyname(self.domain)
            except:
                self.ip_address = self.domain
        else:
            self.ip_address = self.domain
        
        # A recording session captures every request/response so findings can
        # be given a proof of concept. It behaves exactly like requests.Session.
        self.session = RecordingSession() if record_evidence \
            else requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.results = []
        self.findings = []
        self.scan_config = {
            'deep_scan': True,
            'aggressive_mode': False,
            'test_wordpress': False,
            'stealth_mode': False
        }
        self.detected_technologies = []
        # Full architecture breakdown, filled in by detect_technologies()
        self.tech_fingerprint = None
        self.firewall_detected = None
        self.rate_limits = {}
        self.scan_modules = scan_modules or ['all']
        self.cancel_event = threading.Event()
        self.module_status = {}
        self.completed_modules = 0
        self.current_step = 'Queued'
        self.scanner_init_errors = {}
        # Structured recon output surfaced by some scanners (e.g. parameters)
        self.discovered_parameters = []
        # Counts of how many findings carry PoC evidence
        self.evidence_summary = {}
        # How many duplicate findings were collapsed
        self.dedupe_stats = {}

    @property
    def cancelled(self):
        """True once a stop has been requested for this scan."""
        return self.cancel_event.is_set()

    def request_cancel(self):
        """Flag the scan for cancellation at the next module boundary."""
        self.cancel_event.set()

    def progress_percent(self):
        """Overall completion percentage based on finished modules."""
        total = len(self.module_status)
        if not total:
            return 0
        return int(round(100 * self.completed_modules / total))

    
    def attach_module_evidence(self, findings):
        """Attach PoC evidence to a single module's findings immediately.

        Done per module so evidence survives the rolling exchange buffer.
        """
        if not findings or not isinstance(self.session, RecordingSession):
            return
        try:
            attach_poc(findings, self.session.exchanges)
        except Exception as e:
            print(f"PoC attachment error: {e}")

    def attach_evidence(self):
        """Top up PoC evidence on any finding that is still missing it."""
        exchanges = []
        if isinstance(self.session, RecordingSession):
            exchanges = self.session.exchanges
        try:
            fill_missing_poc(self.findings, exchanges)
        except Exception as e:
            print(f"PoC attachment error: {e}")
        self.evidence_summary = summarise_poc(
            [f.get('poc', {}) for f in self.findings
             if isinstance(f, dict)]
        )
        return self.evidence_summary

    def is_duplicate_finding(self, new_finding):
        """Check whether an identical finding has already been collected.

        Uses the shared identity rules (vulnerability class, normalised
        location, parameter) so the same issue proven with a different payload
        is recognised as the same finding.
        """
        key = finding_identity(new_finding)
        for existing in self.findings:
            if finding_identity(existing) == key:
                return True
        return False

    def add_finding(self, finding, module=None):
        """Record a finding, tagging the module that produced it.

        Duplicates are allowed in here and merged once at the end, because
        merging on arrival would discard whichever copy carried the better
        proof of concept.
        """
        if not isinstance(finding, dict):
            return
        if module:
            finding.setdefault('module', module)
        self.findings.append(finding)

    def dedupe_findings(self):
        """Collapse duplicate findings and sort by severity.

        Returns the dedupe statistics so the report can show how many
        duplicates were merged.
        """
        try:
            unique, stats = dedupe(self.findings)
        except Exception as e:
            print(f"Deduplication error: {e}")
            return {'original': len(self.findings), 'unique': len(self.findings),
                    'merged': 0, 'invalid_skipped': 0}
        self.findings = sort_findings(unique)
        self.dedupe_stats = stats
        return stats
        
    def detect_technologies(self):
        """Fingerprint the target and record the detected technologies.

        Uses the TechFingerprint module (headers, cookies, body, error page)
        so the results are far more accurate than a single string match, and
        the full breakdown is kept for the UI.
        """
        if self.is_ip:
            return

        try:
            fingerprint = TechFingerprint(self.target_url, self.session)
            fingerprint.scan()

            # Keep the structured report for the results payload
            self.tech_fingerprint = {
                'architecture': fingerprint.architecture,
                'summary': fingerprint.summary(),
                'evidence': fingerprint.evidence,
                'has_database': fingerprint.has_database_evidence(),
                'databases': [
                    i['name'] for i in fingerprint.architecture.get('databases', [])
                ],
            }

            # CVEScanner matches on these names, so merge the flat list
            for tech in fingerprint.technologies:
                if tech not in self.detected_technologies:
                    self.detected_technologies.append(tech)

        except Exception as e:
            print(f"Technology detection error: {e}")
            
    def build_scanners(self):
        """Instantiate every scanner enabled by the current module selection.

        Returns an ordered dict so the scan runner executes modules in a
        predictable order no matter how the selection was made.
        """
        scanners = {}
        errors = {}
        mods = self.scan_modules
        run_all = 'all' in mods
        web = run_all or 'web' in mods
        network = run_all or 'network' in mods

        def add(key, factory):
            """Build one scanner, isolating init failures to that module.

            A single misconfigured module must not abort the entire scan, so
            failures are recorded and the remaining modules still run.
            """
            try:
                scanners[key] = factory()
            except Exception as exc:
                errors[key] = str(exc)
                print(f"{key} scanner init error: {exc}")

        # Initialize scanners based on selected modules
        if web or 'sqli' in mods:
            add('sqli', lambda: SQLiScanner(self.target_url, self.session))
        if web or 'xss' in mods:
            add('xss', lambda: XSSScanner(self.target_url, self.session))
        if web or 'idor' in mods:
            add('idor', lambda: IDORScanner(self.target_url, self.session))
        if web or 'lfi' in mods:
            add('lfi', lambda: LFIScanner(self.target_url, self.session))
        if web or 'cmd' in mods:
            add('cmd', lambda: CommandInjectionScanner(self.target_url, self.session))
        if web or 'upload' in mods:
            add('upload', lambda: FileUploadScanner(self.target_url, self.session))
        if web or 'graphql' in mods:
            add('graphql', lambda: GraphQLScanner(self.target_url, self.session))
        if run_all or 'api' in mods:
            add('api', lambda: APIScanner(self.target_url, self.session))
        if run_all or 'cloud' in mods:
            add('cloud', lambda: CloudScanner(self.target_url, self.domain, self.session))
        if run_all or 'cve' in mods:
            add('cve', lambda: CVEScanner(self.domain, self.detected_technologies))
        if run_all or web or 'wordpress' in mods or 'wp' in mods:
            # Registered internally as 'wp'; the frontend id is 'wordpress',
            # so accept either spelling.
            add('wp', lambda: WordPressScanner(self.target_url, self.session))
        if run_all or 'general' in mods:
            add('general', lambda: GeneralScanner(self.target_url, self.session))
        if run_all or network or 'ports' in mods or 'port' in mods:
            # Registered internally as 'port'; the frontend id is 'ports'.
            add('port', lambda: PortScanner(
                self.domain,
                scan_all=self.is_ip or self.scan_config.get('deep_scan', True),
            ))
        if run_all or network or 'firewall' in mods:
            add('firewall', lambda: FirewallDetector(self.target_url, self.session))
        if run_all or network or 'rate' in mods:
            add('rate', lambda: RateLimitTester(self.target_url, self.session))
        if web or 'redirect' in mods:
            add('redirect', lambda: OpenRedirectScanner(self.target_url, self.session))
        if web or 'ai' in mods:
            add('ai', lambda: AIScanner(self.target_url, self.session))
        if run_all or 'fuzz' in mods or 'directories' in mods:
            def _fuzz():
                from scanner_modules.fuzzer import Fuzzer
                return Fuzzer(self.target_url, self.session)
            add('fuzz', _fuzz)
        if run_all or 'subdomain' in mods:
            def _subdomain():
                from scanner_modules.subdomain_enum import SubdomainEnumerator
                return SubdomainEnumerator(self.target_url, self.session)
            add('subdomain', _subdomain)
        if run_all or 'sitemap' in mods:
            def _sitemap():
                from scanner_modules.site_mapper import SiteMapper
                return SiteMapper(self.target_url, self.session)
            add('sitemap', _sitemap)
        if web or 'ssrf' in mods:
            add('ssrf', lambda: SSRFScanner(self.target_url, self.session))
        if web or 'xxe' in mods:
            add('xxe', lambda: XXEScanner(self.target_url, self.session))
        if web or 'ssti' in mods:
            add('ssti', lambda: SSTIScanner(self.target_url, self.session))
        if web or 'deser' in mods:
            add('deser', lambda: DeserializationScanner(self.target_url, self.session))
        if run_all or 'params' in mods:
            # Parameter discovery is recon, not a vulnerability probe
            add('params', lambda: ParamDiscovery(self.target_url, self.session))
        if run_all or 'fingerprint' in mods or 'tech' in mods:
            add('fingerprint',
                lambda: TechFingerprint(self.target_url, self.session))

        self.scanner_init_errors = errors
        return scanners

    def run_full_scan(self, scan_id, progress_callback=None):
        """Execute comprehensive vulnerability scan"""
        try:
            scanners = self.build_scanners()

            # Calculate progress steps
            total_scanners = len(scanners)
            self.module_status = {
                key: {'status': 'pending', 'findings': 0} for key in scanners
            }
            if total_scanners == 0:
                scan_results[scan_id] = {
                    'error': 'No scanner modules matched the selection',
                    'findings': [],
                }
                active_scans[scan_id]['status'] = 'completed'
                active_scans[scan_id]['current_step'] = 'No modules selected'
                return

            self.completed_modules = 0
            self.current_step = 'Starting scan'

            def report(message, module_key=None):
                """Publish progress for the UI and check for cancellation."""
                if self.cancelled:
                    raise ScanCancelled()
                self.current_step = message
                if module_key and module_key in self.module_status:
                    self.module_status[module_key]['status'] = 'running'
                if progress_callback:
                    progress_callback(scan_id, message, self.progress_percent())

            def complete_module(module_key):
                """Mark a module finished and bump the completion counter."""
                if module_key in self.module_status:
                    self.module_status[module_key]['status'] = 'completed'
                self.completed_modules += 1

            def fail_module(module_key, exc):
                """Mark a module failed without aborting the whole scan."""
                if module_key in self.module_status:
                    self.module_status[module_key]['status'] = 'failed'
                    self.module_status[module_key]['error'] = str(exc)
                self.completed_modules += 1
                print(f"{module_key} scanner error: {exc}")

            # Step 1: Technology Detection (if web scan)
            if not self.is_ip and ('all' in self.scan_modules or 'web' in self.scan_modules or 'general' in self.scan_modules):
                report("Detecting technologies...")
                self.detect_technologies()

            # Step 2: Port Scanning
            if 'port' in scanners:
                report("Scanning open ports...", 'port')
                try:
                    open_ports = scanners['port'].scan(scan_all=scanners['port'].scan_all)
                    self.results.append({'type': 'Port Scan', 'data': open_ports})
                    self.results.append({'type': 'Port Scan Results', 'data': scanners['port'].scan_results})
                    # Collect port scanner findings (version, auth, CVE)
                    for finding in scanners['port'].findings:
                        self.add_finding(finding, 'port')
                    self.module_status['port']['findings'] = len(scanners['port'].findings)
                except Exception as e:
                    fail_module('port', e)
                else:
                    complete_module('port')

            # Step 3: Firewall Detection
            if not self.is_ip and 'firewall' in scanners:
                report("Detecting firewall/WAF...", 'firewall')
                try:
                    # FirewallDetector exposes scan(); it returns a findings
                    # list. detect_waf() is already called inside scan(), so
                    # read the detected name off the finding rather than
                    # repeating the network request.
                    findings = scanners['firewall'].scan() or []
                    for finding in findings:
                        self.add_finding(finding, 'firewall')
                    title = next(
                        (f.get('title', '') for f in findings if f.get('type') == 'Firewall'),
                        '',
                    )
                    # "No WAF detected" means nothing was found
                    self.firewall_detected = None if 'No WAF' in title else (title or True)
                    self.module_status['firewall']['findings'] = len(findings)
                except Exception as e:
                    fail_module('firewall', e)
                else:
                    complete_module('firewall')

            # Step 4: Rate Limit Testing
            if not self.is_ip and 'rate' in scanners:
                report("Testing rate limits...", 'rate')
                try:
                    results = scanners['rate'].scan() or {}
                    self.rate_limits = results
                    rate_findings = scanners['rate'].findings or []
                    for finding in rate_findings:
                        self.add_finding(finding, 'rate')
                    self.module_status['rate']['findings'] = len(rate_findings)
                except Exception as e:
                    fail_module('rate', e)
                else:
                    complete_module('rate')

            # Step 5: General Information Gathering
            if 'general' in scanners and not self.is_ip:
                report("Gathering information...", 'general')
                try:
                    scanners['general'].scan()
                    for finding in scanners['general'].findings:
                        self.add_finding(finding, 'general')
                    self.module_status['general']['findings'] = len(scanners['general'].findings)
                except Exception as e:
                    fail_module('general', e)
                else:
                    complete_module('general')
            
            # Step 6+: Run the remaining selected scanners
            scanner_names = {
                'cve': 'Checking for CVEs...',
                'sqli': 'Testing SQL Injection...',
                'xss': 'Testing XSS...',
                'idor': 'Testing IDOR...',
                'lfi': 'Testing LFI...',
                'cmd': 'Testing Command Injection...',
                'graphql': 'Testing GraphQL...',
                'api': 'Testing API Security...',
                'cloud': 'Testing Cloud Security...',
                'wp': 'Testing WordPress vulnerabilities...',
                'ai': 'Testing AI/LLM Security (OWASP Top 10)...',
                'redirect': 'Testing Open Redirect...',
                'upload': 'Testing File Upload...',
                'fuzz': 'Running Fuzzer...',
                'subdomain': 'Enumerating subdomains...',
                'sitemap': 'Mapping site structure...',
                'ssrf': 'Testing SSRF (Server-Side Request Forgery)...',
                'xxe': 'Testing XXE (XML External Entity)...',
                'ssti': 'Testing SSTI (Server-Side Template Injection)...',
                'deser': 'Testing Insecure Deserialization...',
                'params': 'Discovering URL parameters...',
                'fingerprint': 'Identifying technologies and architecture...',
            }

            for key, scanner in scanners.items():
                # These four already ran as dedicated pre-steps above
                if key in ('port', 'firewall', 'rate', 'general'):
                    continue

                label = scanner_names.get(key, f"Running {key.upper()}...")
                report(label, key)

                try:
                    if hasattr(scanner, 'scan'):
                        findings = scanner.scan()
                        if findings:
                            # Attach evidence now, while this module's requests
                            # are still in the buffer
                            self.attach_module_evidence(findings)
                            # Duplicates are merged once at the end, keeping the best PoC
                            for finding in findings:
                                self.add_finding(finding, key)
                        self.module_status[key]['findings'] = len(findings or [])

                    # Scanners may also expose structured recon output
                    discovered = getattr(scanner, 'discovered_parameters', None)
                    if isinstance(discovered, list) and discovered:
                        self.discovered_parameters.extend(discovered)
                except Exception as e:
                    fail_module(key, e)
                else:
                    complete_module(key)

            # Complete
            self.current_step = 'Scan complete!'

            # Merge duplicate findings, then attach proof-of-concept evidence

            self.dedupe_findings()

            self.attach_evidence()

            # Compile results
            port_entry = next(
                (r for r in self.results if r.get('type') == 'Port Scan'), None
            )
            scan_results[scan_id] = {
                'target': self.target_url,
                'domain': self.domain,
                'ip_address': self.ip_address,
                'is_ip': self.is_ip,
                'technologies': self.detected_technologies,
                'architecture': self.tech_fingerprint,
                'firewall': self.firewall_detected,
                'rate_limits': self.rate_limits,
                'open_ports': port_entry['data'] if port_entry else [],
                'findings': self.findings,
                'module_status': self.module_status,
                'modules_run': list(self.module_status.keys()),
                'modules_failed_to_init': self.scanner_init_errors,
                'parameters': self.discovered_parameters,
                'evidence_summary': self.evidence_summary,
                'dedupe_stats': self.dedupe_stats,
                'cancelled': False,
                'statistics': {
                    'total_findings': len(self.findings),
                    'critical': sum(1 for f in self.findings if f.get('severity') == 'Critical'),
                    'high': sum(1 for f in self.findings if f.get('severity') == 'High'),
                    'medium': sum(1 for f in self.findings if f.get('severity') == 'Medium'),
                    'low': sum(1 for f in self.findings if f.get('severity') == 'Low'),
                    'info': sum(1 for f in self.findings if f.get('severity') == 'Info')
                },
                'completed_at': datetime.now().isoformat()
            }

            active_scans[scan_id]['status'] = 'completed'
            active_scans[scan_id]['current_step'] = 'Scan complete!'
            if progress_callback:
                progress_callback(scan_id, "Scan complete!", 100)

        except ScanCancelled:
            # User stopped the scan - keep whatever was already collected.
            active_scans[scan_id]['status'] = 'cancelled'
            active_scans[scan_id]['current_step'] = 'Scan stopped'
            self.dedupe_findings()
            self.attach_evidence()
            port_entry = next(
                (r for r in self.results if r.get('type') == 'Port Scan'), None
            )
            scan_results[scan_id] = {
                'target': self.target_url,
                'domain': self.domain,
                'ip_address': self.ip_address,
                'is_ip': self.is_ip,
                'technologies': self.detected_technologies,
                'architecture': self.tech_fingerprint,
                'firewall': self.firewall_detected,
                'rate_limits': self.rate_limits,
                'open_ports': port_entry['data'] if port_entry else [],
                'findings': self.findings,
                'module_status': self.module_status,
                'modules_run': list(self.module_status.keys()),
                'modules_failed_to_init': self.scanner_init_errors,
                'parameters': self.discovered_parameters,
                'evidence_summary': self.evidence_summary,
                'dedupe_stats': self.dedupe_stats,
                'cancelled': True,
                'statistics': {
                    'total_findings': len(self.findings),
                    'critical': sum(1 for f in self.findings if f.get('severity') == 'Critical'),
                    'high': sum(1 for f in self.findings if f.get('severity') == 'High'),
                    'medium': sum(1 for f in self.findings if f.get('severity') == 'Medium'),
                    'low': sum(1 for f in self.findings if f.get('severity') == 'Low'),
                    'info': sum(1 for f in self.findings if f.get('severity') == 'Info')
                },
                'completed_at': datetime.now().isoformat()
            }

        except Exception as e:
            active_scans[scan_id]['status'] = 'error'
            active_scans[scan_id]['error'] = str(e)
            active_scans[scan_id]['current_step'] = 'Scan failed'
            scan_results[scan_id] = {
                'error': str(e),
                'findings': self.findings
            }

def _validate_target(target_url):
    """Return an error message for an invalid target, or None when it is fine."""
    if not target_url or not str(target_url).strip():
        return 'Target URL or IP is required'

    target_url = str(target_url).strip()

    try:
        parsed = urlparse(target_url)
        # A bare IP or hostname is acceptable; anything else needs a real scheme
        if not all([parsed.scheme, parsed.netloc]) and '.' not in target_url:
            return 'Invalid URL or IP format'
        if '..' in target_url:
            return 'Invalid URL or IP format'
    except Exception:
        return 'Invalid URL or IP format'

    return None


def _launch_scan(target_url, scan_modules, scan_config=None):
    """Register a scan and execute it on a background thread.

    Shared by the single-module and the one-click "run everything" endpoints.
    """
    scan_id = f"scan_{uuid.uuid4().hex[:12]}"

    active_scans[scan_id] = {
        'target': target_url,
        'modules': scan_modules,
        'status': 'running',
        'started_at': datetime.now().isoformat(),
        'progress': 0,
        'current_step': 'Initializing scanners...',
        'completed_modules': 0,
        'total_modules': 0,
    }

    # Start scan in background thread
    scanner = VulnerabilityScanner(target_url, scan_modules)
    if scan_config:
        scanner.scan_config.update(scan_config)
    scan_workers[scan_id] = scanner

    def progress_callback(scan_id, message, percent):
        """Mirror scanner progress into the status registry."""
        record = active_scans.get(scan_id)
        if not record:
            return
        record['current_step'] = message
        record['progress'] = percent
        record['completed_modules'] = scanner.completed_modules
        record['total_modules'] = len(scanner.module_status)
        record['module_status'] = scanner.module_status

    def run_scan():
        try:
            scanner.run_full_scan(scan_id, progress_callback=progress_callback)
        finally:
            scan_workers.pop(scan_id, None)

    # Daemon thread so the server can always shut down cleanly
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return scan_id


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new vulnerability scan"""
    data = request.get_json(silent=True) or {}
    target_url = (data.get('target_url') or '').strip()
    # An explicit empty list must stay empty, so check for None rather than
    # relying on truthiness (an empty list is falsy).
    scan_modules = data.get('modules')
    if scan_modules is None:
        scan_modules = ['all']

    error = _validate_target(target_url)
    if error:
        return jsonify({'error': error}), 400

    if not isinstance(scan_modules, list):
        scan_modules = [scan_modules]
    scan_modules = [m for m in scan_modules if m]
    if not scan_modules:
        return jsonify({'error': 'At least one scan module must be selected'}), 400

    scan_id = _launch_scan(target_url, scan_modules, data.get('config'))

    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'target': target_url,
        'modules': scan_modules
    })

@app.route('/api/scan/all', methods=['POST'])
def run_all_scans():
    """One-click "run everything": every scanner module against one target.

    Optionally accepts a list of targets in `targets` to run the full suite
    against several hosts, each as its own independent scan.
    """
    data = request.get_json(silent=True) or {}
    scan_config = data.get('config') or {}

    targets = data.get('targets')
    if not targets:
        single = (data.get('target_url') or '').strip()
        targets = [single] if single else []

    if not targets:
        return jsonify({'error': 'Target URL or IP is required'}), 400

    # Validate every target before launching anything
    cleaned = []
    for target in targets:
        if isinstance(target, str):
            target = target.strip()
        error = _validate_target(target)
        if error:
            return jsonify({'error': f"{target or 'target'}: {error}"}), 400
        cleaned.append(target)

    # Expand "all" so the UI can show every module that will run
    modules = data.get('modules')
    if modules is None:
        modules = ['all']
    if 'all' in modules:
        modules = list(ALL_SCAN_MODULES)
    modules = [m for m in modules if m]
    if not modules:
        return jsonify({'error': 'At least one scan module must be selected'}), 400

    launched = [
        {
            'scan_id': _launch_scan(target, modules, scan_config),
            'target': target,
        }
        for target in cleaned
    ]

    return jsonify({
        'scan_id': launched[0]['scan_id'],
        'scan_ids': [s['scan_id'] for s in launched],
        'status': 'started',
        'target': launched[0]['target'],
        'targets': [s['target'] for s in launched],
        'modules': modules,
        'module_count': len(modules),
    })

@app.route('/api/scan/<scan_id>/stop', methods=['POST'])
def stop_scan(scan_id):
    """Stop a running scan.

    The stop is cooperative: the in-flight module finishes, then the scan halts
    and the partial results collected so far become available.
    """
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404

    scanner = scan_workers.get(scan_id)
    if not scanner:
        return jsonify({'error': 'Scan is not running'}), 409

    if active_scans[scan_id].get('status') != 'running':
        return jsonify({'error': 'Scan is not running'}), 409

    scanner.request_cancel()
    active_scans[scan_id]['current_step'] = 'Stopping after the current module...'

    return jsonify({
        'scan_id': scan_id,
        'status': 'stopping',
        'message': 'Scan will stop once the current module finishes',
    })

@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status"""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan = active_scans[scan_id]
    result = scan_results.get(scan_id, {})
    status = scan.get('status', 'unknown')

    # Live progress comes from the scan record while running, and is pinned to
    # 100% once the scan has finished.
    if status == 'running':
        progress = scan.get('progress', 0)
    else:
        progress = 100 if status in ('completed', 'cancelled') else 0

    return jsonify({
        'scan_id': scan_id,
        'target': scan.get('target'),
        'modules': scan.get('modules'),
        'status': status,
        'started_at': scan.get('started_at'),
        'progress': progress,
        'current_step': scan.get('current_step'),
        'completed_modules': scan.get('completed_modules', 0),
        'total_modules': scan.get('total_modules', 0),
        'module_status': scan.get('module_status', {}),
        'findings_count': result.get('statistics', {}).get('total_findings', 0),
        'error': scan.get('error')
    })

@app.route('/api/scan/modules', methods=['GET'])
def list_scan_modules():
    """List every module the one-click flow can run."""
    return jsonify({
        'modules': ALL_SCAN_MODULES,
        'count': len(ALL_SCAN_MODULES),
    })

@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get scan results"""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not ready'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/api/scan/<scan_id>/report', methods=['GET'])
def download_report(scan_id):
    """Download scan report"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Report not ready'}), 404
    
    result = scan_results[scan_id]
    
    # Generate HTML report
    report_html = generate_html_report(result)
    
    # Save report
    report_path = os.path.join('reports', f'{scan_id}_report.html')
    os.makedirs('reports', exist_ok=True)
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_html)
    
    return send_file(report_path, as_attachment=True, download_name=f'red_dragon_report_{scan_id}.html')

def esc(value):
    """HTML-escape any value.

    Findings carry attacker-controlled data (URLs, payloads, and now response
    bodies), so everything interpolated into the report must be escaped or a
    reflected XSS payload would execute when the report is opened.
    """
    import html
    return html.escape(str(value if value is not None else ''), quote=True)


def _render_merged_html(finding):
    """Render details gathered while merging duplicate reports of a finding.

    Every value here originates from the target, so each one is escaped.
    """
    payloads = [str(p) for p in (finding.get('payloads') or []) if p]
    evidence = [str(e) for e in (finding.get('evidence_list') or []) if e]
    variants = [str(v) for v in (finding.get('variants') or []) if v]
    modules = [str(m) for m in (finding.get('modules') or []) if m]
    try:
        merged = int(finding.get('merged_count') or 0)
    except (TypeError, ValueError):
        merged = 0

    if not any((merged, payloads, evidence, variants, modules)):
        return ''

    parts = ['<details class="poc"><summary>Corroborating detail</summary>']
    if merged:
        parts.append(
            f'<div class="poc-note">{merged + 1} reports of this issue were '
            f'merged into one finding.</div>')
    if modules:
        parts.append(
            f'<div><strong>Reported by:</strong> {esc(", ".join(modules))}</div>')
    if payloads:
        parts.append('<div style="margin-top:8px;"><strong>Payloads that '
                     'confirmed this issue:</strong></div><ul>')
        parts.extend(f'<li><code>{esc(p)}</code></li>' for p in payloads)
        parts.append('</ul>')
    if evidence:
        parts.append('<div style="margin-top:8px;"><strong>Evidence</strong></div><ul>')
        parts.extend(f'<li>{esc(e)}</li>' for e in evidence)
        parts.append('</ul>')
    if variants:
        parts.append('<div style="margin-top:8px;"><strong>Also detected as</strong></div><ul>')
        parts.extend(f'<li>{esc(v)}</li>' for v in variants)
        parts.append('</ul>')
    parts.append('</details>')
    return ''.join(parts)


def _render_poc_html(poc):
    """Render a finding's proof-of-concept as a collapsible evidence block."""
    if not poc:
        return ''

    location = poc.get('location') or {}
    parts = ['<details class="poc"><summary>Proof of Concept</summary>']

    # Where it was found
    parts.append('<div class="poc-where"><strong>Location</strong>')
    parts.append(
        f'<div>Method: <code>{esc(location.get("method", "GET"))}</code></div>')
    parts.append(
        f'<div>Endpoint: <code>{esc(location.get("endpoint", ""))}</code></div>')
    if location.get('request_url'):
        parts.append(
            f'<div>Request URL: <code>{esc(location.get("request_url"))}</code></div>')
    if location.get('parameter'):
        parts.append(
            f'<div>Parameter: <code>{esc(location.get("parameter"))}</code></div>')
    parts.append('</div>')

    if not poc.get('available'):
        parts.append(
            f'<div class="poc-note">{esc(poc.get("reason", "No evidence captured."))}</div>')
        parts.append('</details>')
        return ''.join(parts)

    # The request that was sent
    request = poc.get('request') or {}
    parts.append('<div class="poc-block"><strong>Request</strong>')
    if request.get('curl'):
        parts.append(f'<pre class="poc-pre">{esc(request.get("curl"))}</pre>')
    headers = request.get('headers') or {}
    if headers:
        parts.append('<div class="poc-headers">')
        for name, value in headers.items():
            parts.append(f'<div><code>{esc(name)}: {esc(value)}</code></div>')
        parts.append('</div>')
    if request.get('body'):
        parts.append(f'<pre class="poc-pre">{esc(request.get("body"))}</pre>')
    parts.append('</div>')

    # The response that proved it
    response = poc.get('response') or {}
    parts.append('<div class="poc-block"><strong>Response</strong>')
    parts.append(
        f'<div>Status: <code>{esc(response.get("status"))}</code> '
        f'({esc(response.get("body_length"))} bytes)</div>')
    if response.get('excerpt'):
        parts.append(
            f'<pre class="poc-pre poc-evidence">{esc(response.get("excerpt"))}</pre>')
    resp_headers = response.get('headers') or {}
    if resp_headers:
        parts.append('<div class="poc-headers">')
        for name, value in resp_headers.items():
            parts.append(f'<div><code>{esc(name)}: {esc(value)}</code></div>')
        parts.append('</div>')
    parts.append('</div>')

    # What exactly proved the vulnerability
    marker = poc.get('marker') or {}
    if marker.get('value'):
        parts.append('<div class="poc-block"><strong>Marker</strong>')
        parts.append(f'<div>Type: <code>{esc(marker.get("type"))}</code></div>')
        if marker.get('offset') is not None:
            parts.append(
                f'<div>Found at byte offset: <code>{esc(marker.get("offset"))}</code></div>')
        parts.append(f'<pre class="poc-pre">{esc(marker.get("value"))}</pre>')
        if marker.get('description'):
            parts.append(
                f'<div class="poc-note">{esc(marker.get("description"))}</div>')
        parts.append('</div>')

    # Comparison against the clean request
    baseline = poc.get('baseline')
    if baseline:
        parts.append('<div class="poc-block"><strong>Baseline request</strong>')
        parts.append(f'<div>URL: <code>{esc(baseline.get("url"))}</code></div>')
        parts.append(
            f'<div>Status <code>{esc(baseline.get("status"))}</code>, '
            f'{esc(baseline.get("body_length"))} bytes</div>')
        parts.append('</div>')

    parts.append('</details>')
    return ''.join(parts)


def generate_html_report(result):
    """Generate professional HTML report"""
    stats = result.get('statistics', {})
    findings = result.get('findings', [])
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Red Dragon Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a1a; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: #252525; border-radius: 10px; padding: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        h1 {{ color: #00d4ff; border-bottom: 3px solid #00d4ff; padding-bottom: 15px; margin-bottom: 30px; }}
        .header-info {{ background: #1e1e1e; padding: 20px; border-radius: 8px; margin-bottom: 30px; border-left: 5px solid #00d4ff; }}
        .header-info h2 {{ color: #00d4ff; margin-bottom: 15px; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }}
        .info-item {{ background: #2a2a2a; padding: 12px; border-radius: 5px; }}
        .info-label {{ color: #888; font-size: 12px; text-transform: uppercase; margin-bottom: 5px; }}
        .info-value {{ color: #fff; font-size: 14px; font-weight: 600; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 30px 0; }}
        .stat-card {{ padding: 20px; border-radius: 8px; text-align: center; font-weight: bold; }}
        .stat-critical {{ background: linear-gradient(135deg, #dc3545, #c82333); color: white; }}
        .stat-high {{ background: linear-gradient(135deg, #fd7e14, #e8590c); color: white; }}
        .stat-medium {{ background: linear-gradient(135deg, #ffc107, #d39e00); color: #333; }}
        .stat-low {{ background: linear-gradient(135deg, #17a2b8, #138496); color: white; }}
        .stat-info {{ background: linear-gradient(135deg, #6c757d, #5a6268); color: white; }}
        .stat-number {{ font-size: 32px; margin-bottom: 5px; }}
        .findings-section {{ margin-top: 40px; }}
        .finding-card {{ background: #1e1e1e; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 5px solid #00d4ff; box-shadow: 0 2px 4px rgba(0,0,0,0.2); }}
        .finding-card.critical {{ border-left-color: #dc3545; }}
        .finding-card.high {{ border-left-color: #fd7e14; }}
        .finding-card.medium {{ border-left-color: #ffc107; }}
        .finding-card.low {{ border-left-color: #17a2b8; }}
        .finding-card.info {{ border-left-color: #6c757d; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; }}
        .finding-title {{ color: #00d4ff; font-size: 20px; font-weight: bold; }}
        .finding-type {{ background: #00d4ff; color: #1a1a1a; padding: 5px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; text-transform: uppercase; }}
        .severity-badge {{ padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: bold; text-transform: uppercase; }}
        .severity-critical {{ background: #dc3545; color: white; }}
        .severity-high {{ background: #fd7e14; color: white; }}
        .severity-medium {{ background: #ffc107; color: #333; }}
        .severity-low {{ background: #17a2b8; color: white; }}
        .severity-info {{ background: #6c757d; color: white; }}
        .finding-details {{ color: #b0b0b0; line-height: 1.6; margin-top: 10px; }}
        .finding-url {{ background: #2a2a2a; padding: 10px; border-radius: 5px; font-family: monospace; color: #00ff00; margin-top: 10px; word-break: break-all; }}
        .section-title {{ color: #00d4ff; font-size: 24px; margin-top: 40px; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #00d4ff; }}
        .technology-tags {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 10px; }}
        .tech-tag {{ background: #00d4ff; color: #1a1a1a; padding: 5px 12px; border-radius: 15px; font-size: 12px; font-weight: 600; }}
        .footer {{ text-align: center; margin-top: 50px; padding-top: 20px; border-top: 1px solid #333; color: #888; }}
        .poc {{ margin-top: 12px; border: 1px solid rgba(255,193,7,0.4); border-radius: 6px; background: rgba(255,193,7,0.06); padding: 8px 12px; }}
        .poc summary {{ cursor: pointer; font-weight: 700; color: #ffc107; font-size: 13px; outline: none; }}
        .poc-where {{ margin: 8px 0; font-size: 12px; word-break: break-all; }}
        .poc-block {{ margin: 8px 0; font-size: 12px; }}
        .poc-block > strong {{ color: #ffc107; }}
        .poc-pre {{ background: #111; color: #d4d4d4; border: 1px solid #333; border-radius: 4px; padding: 8px; margin: 6px 0; white-space: pre-wrap; word-break: break-all; font-family: Consolas, Monaco, monospace; font-size: 11px; max-height: 320px; overflow: auto; }}
        .poc-evidence {{ border-color: #ffc107; color: #ffe082; }}
        .poc-headers {{ color: #9e9e9e; word-break: break-all; }}
        .poc-note {{ color: #bdbdbd; font-style: italic; margin: 4px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Red Dragon Scan Report</h1>
        
        <div class="header-info">
            <h2>Scan Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Target</div>
                    <div class="info-value">{result.get('target', 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Domain/IP</div>
                    <div class="info-value">{result.get('domain', 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">IP Address</div>
                    <div class="info-value">{result.get('ip_address', 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Scan Date</div>
                    <div class="info-value">{result.get('completed_at', 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Firewall Detected</div>
                    <div class="info-value" style="color: {'#ffc107' if result.get('firewall') else '#28a745'}">
                        {result.get('firewall', 'None') if result.get('firewall') else 'None detected'}
                    </div>
                </div>
                <div class="info-item">
                    <div class="info-label">Scan Type</div>
                    <div class="info-value">{'IP Scan' if result.get('is_ip') else 'URL Scan'}</div>
                </div>
            </div>
        </div>
        
        <div class="section-title">Detected Technologies</div>
        <div class="technology-tags">
            {"".join([f'<span class="tech-tag">{tech}</span>' for tech in result.get('technologies', [])]) if result.get('technologies') else '<span class="tech-tag">None detected</span>'}
        </div>
        
        <div class="section-title">Statistics Overview</div>
        <div class="stats-grid">
            <div class="stat-card stat-critical">
                <div class="stat-number">{stats.get('critical', 0)}</div>
                <div>Critical</div>
            </div>
            <div class="stat-card stat-high">
                <div class="stat-number">{stats.get('high', 0)}</div>
                <div>High</div>
            </div>
            <div class="stat-card stat-medium">
                <div class="stat-number">{stats.get('medium', 0)}</div>
                <div>Medium</div>
            </div>
            <div class="stat-card stat-low">
                <div class="stat-number">{stats.get('low', 0)}</div>
                <div>Low</div>
            </div>
            <div class="stat-card stat-info">
                <div class="stat-number">{stats.get('info', 0)}</div>
                <div>Informational</div>
            </div>
        </div>
        
        <div class="section-title">Detailed Findings</div>
        <div class="findings-section">
    '''
    
    for finding in findings:
        severity = finding.get('severity', 'Info')
        finding_type = finding.get('type', 'Unknown')

        # Evidence is rendered as a collapsible block under the finding
        poc_block = _render_poc_html(finding.get('poc') or {})

        # Details gathered when duplicate reports of this issue were merged
        merged_block = _render_merged_html(finding)

        html += f'''
            <div class="finding-card {severity.lower()}">
                <div class="finding-header">
                    <div class="finding-title">{esc(finding.get('title', 'Unknown Finding'))}</div>
                    <div style="display: flex; gap: 10px;">
                        <span class="finding-type">{esc(finding_type)}</span>
                        <span class="severity-badge severity-{severity.lower()}">{esc(severity)}</span>
                    </div>
                </div>
                <div class="finding-details">
                    <p>{esc(finding.get('description', 'No description'))}</p>
                    {"<div class='finding-url'>URL: " + esc(finding.get('url', '')) + "</div>" if finding.get('url') else ""}
                    {merged_block}
                    {poc_block}
                    <p style="margin-top: 10px;"><strong>Remediation:</strong> {esc(finding.get('remediation', 'N/A'))}</p>
                    <p style="margin-top: 5px;"><strong>Risk Level:</strong> {esc(severity)}</p>
                </div>
            </div>
        '''
    
    html += '''
        </div>
        <div class="footer">
            <p>Generated by Red Dragon v1.0.0 by aegis cyber works</p>
            <p style="font-size: 12px; margin-top: 5px;">Report generated on ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
        </div>
    </div>
</body>
</html>
    '''
    
    return html

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'active_scans': len(active_scans),
        'completed_scans': len(scan_results)
    })

@app.route('/api/ai/providers', methods=['GET'])
def get_ai_providers():
    """Get available AI providers"""
    providers = ai_agent.get_available_providers()
    return jsonify({
        'providers': [
            {
                'id': key,
                'name': val['name'],
                'models': val['models'],
                'default_model': val['default_model']
            }
            for key, val in providers.items()
        ]
    })

@app.route('/api/ai/configure', methods=['POST'])
def configure_ai():
    """Configure AI provider"""
    data = request.get_json()
    provider = data.get('provider')
    api_key = data.get('api_key')
    model = data.get('model')
    
    if not provider or not api_key:
        return jsonify({'error': 'Provider and API key are required'}), 400
    
    result = ai_agent.set_provider(provider, api_key, model)
    return jsonify(result)

@app.route('/api/ai/chat', methods=['POST'])
def ai_chat():
    """AI Chat endpoint"""
    data = request.get_json()
    message = data.get('message')
    provider = data.get('provider')
    api_key = data.get('api_key')
    model = data.get('model')
    scan_context = data.get('scan_context')
    
    if not message:
        return jsonify({'error': 'Message is required'}), 400
    
    # Configure provider if credentials provided
    if provider and api_key:
        ai_agent.set_provider(provider, api_key, model)
    
    result = ai_agent.chat(message, scan_context)
    return jsonify(result)

@app.route('/api/ai/analyze', methods=['POST'])
def ai_analyze():
    """AI Analysis endpoint"""
    data = request.get_json()
    scan_results_data = data.get('scan_results')
    provider = data.get('provider')
    api_key = data.get('api_key')
    model = data.get('model')
    
    if not scan_results_data:
        return jsonify({'error': 'Scan results are required'}), 400
    
    # Configure provider if credentials provided
    if provider and api_key:
        ai_agent.set_provider(provider, api_key, model)
    
    result = ai_agent.analyze_findings(scan_results_data)
    return jsonify(result)

# ============ AI SECURITY AGENT (session scoped) ============
#
# The endpoints above share one module-level agent, so the API key and
# conversation history leak between every caller of the process. The agent
# below is instantiated per session instead, so a user's key is only ever held
# in memory for their own session and is never returned in any response.

ai_sessions = {}
AI_SESSION_TTL_SECONDS = 6 * 60 * 60


def _prune_ai_sessions():
    """Drop expired sessions so keys are not held indefinitely."""
    if not ai_sessions:
        return
    cutoff = datetime.now() - timedelta(seconds=AI_SESSION_TTL_SECONDS)
    for session_id, record in list(ai_sessions.items()):
        try:
            last_used = datetime.fromisoformat(record['agent'].last_used)
        except Exception:
            last_used = datetime.now()
        if last_used < cutoff:
            ai_sessions.pop(session_id, None)


def _get_agent(session_id):
    """Return the agent for a session id, or None."""
    if not session_id:
        return None
    _prune_ai_sessions()
    record = ai_sessions.get(session_id)
    return record['agent'] if record else None


def _resolve_scan_results(data):
    """Prefer a live scan by id, falling back to results sent by the client."""
    scan_id = data.get('scan_id')
    if scan_id and scan_id in scan_results:
        return scan_results[scan_id]
    return data.get('scan_results') or None


@app.route('/api/ai/session', methods=['POST'])
def create_ai_session():
    """Create an AI agent session using a user-supplied API key.

    The key configures a per-session agent and is never echoed back.
    """
    data = request.get_json(silent=True) or {}
    provider = data.get('provider')
    api_key = (data.get('api_key') or '').strip()
    model = data.get('model')

    if not provider or not api_key:
        return jsonify({
            'error': 'Provider and API key are both required'
        }), 400

    # The model name is user input: accept any name the provider offers, but
    # reject malformed values here so the caller gets a precise error instead
    # of the generic "could not initialise client" message below.
    try:
        model = normalize_model_name(model)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    agent = SecurityAgent(provider=provider, api_key=api_key, model=model)

    if not agent.client:
        available = ', '.join(agent.providers.keys())
        return jsonify({
            'error': (
                f'Could not initialise the {provider} client. Make sure the '
                f'provider SDK is installed (available: {available}).'
            )
        }), 400

    session_id = data.get('session_id')
    if session_id and session_id in ai_sessions:
        # Re-keying an existing session keeps its conversation going
        ai_sessions[session_id]['agent'] = agent
        agent.session_id = session_id
    else:
        session_id = agent.session_id
        ai_sessions[session_id] = {
            'agent': agent, 'created_at': datetime.now().isoformat()}

    # Confirm the credentials actually work before reporting success
    verification = agent.verify_credentials()

    return jsonify({
        'session_id': session_id,
        'configured': True,
        'verified': verification.get('success', False),
        'provider': provider,
        'provider_name': agent.providers.get(provider, {}).get('name'),
        'model': agent.model,
        'message': (
            'Connected' if verification.get('success')
            else 'Session created, but the provider rejected the request'
        ),
        'warning': None if verification.get('success')
                   else verification.get('error'),
    }), 200 if verification.get('success') else 502


@app.route('/api/ai/session/<session_id>', methods=['GET'])
def get_ai_session(session_id):
    """Describe a session. Deliberately never returns the API key."""
    agent = _get_agent(session_id)
    if not agent:
        return jsonify({'error': 'Session not found or expired'}), 404
    return jsonify(agent.describe())


@app.route('/api/ai/session/<session_id>', methods=['DELETE'])
def delete_ai_session(session_id):
    """Destroy a session, discarding the API key and chat history."""
    if session_id not in ai_sessions:
        return jsonify({'error': 'Session not found'}), 404
    agent = ai_sessions.pop(session_id)['agent']
    # Drop references so the key is not reachable from the agent object
    agent.api_key = None
    agent.client = None
    agent.conversation_history = []
    return jsonify({'success': True, 'message': 'Session ended'})


def _agent_action(session_id, action):
    """Shared plumbing for the agent endpoints."""
    agent = _get_agent(session_id)
    if not agent:
        return jsonify({'error': 'AI session not found or expired'}), 404
    if not agent.client:
        return jsonify({'error': 'AI session is not configured'}), 400

    data = request.get_json(silent=True) or {}
    results = _resolve_scan_results(data)

    try:
        if action == 'ask':
            question = data.get('question')
            if not question:
                return jsonify({'error': 'A question is required'}), 400
            payload = agent.ask(question, results)
        elif action == 'report':
            payload = agent.generate_report(
                results, audience=data.get('audience', 'technical'))
        elif action == 'attack-plan':
            if not data.get('authorised'):
                return jsonify({
                    'error': (
                        'Confirm you have written permission to test this target '
                        'before requesting an attack plan.'
                    )
                }), 400
            payload = agent.build_attack_plan(
                results, scope_note=data.get('scope_note', ''))
        else:
            return jsonify({'error': 'Unknown action'}), 400
    except Exception as e:
        return jsonify({'error': f'AI request failed: {str(e)}'}), 500

    if payload.get('error'):
        return jsonify(payload), 502

    payload['used_scan_context'] = bool(results)
    payload['session_id'] = agent.session_id
    return jsonify(payload)


@app.route('/api/ai/agent/ask', methods=['POST'])
def ai_agent_ask():
    """Ask the AI agent a question about the target."""
    return _agent_action(
        (request.get_json(silent=True) or {}).get('session_id'), 'ask')


@app.route('/api/ai/agent/report', methods=['POST'])
def ai_agent_report():
    """Generate a security report from the scan results."""
    return _agent_action(
        (request.get_json(silent=True) or {}).get('session_id'), 'report')


@app.route('/api/ai/agent/attack-plan', methods=['POST'])
def ai_agent_attack_plan():
    """Build an attack/test plan (authorised use only)."""
    return _agent_action(
        (request.get_json(silent=True) or {}).get('session_id'), 'attack-plan')

# Register extensions
# A failure here used to be swallowed into a one-line note, which hid a real
# bug: a duplicate /api/ai/configure route aborted the whole registration pass
# and silently dropped every extension endpoint. Print the traceback so the
# next one cannot hide.
try:
    from server_extensions import register_extensions
    register_extensions(app)
except Exception as e:
    import traceback
    print(f"Note: Extension endpoints not loaded: {e}")
    traceback.print_exc()


# ============ MULTI-TARGET SCANNING ============

@app.route('/api/scan/multi', methods=['POST'])
def scan_multi_target():
    """Scan multiple targets (domains/IPs) in one request."""
    data = request.get_json()
    targets = data.get('targets', [])
    scan_modules = data.get('modules', ['all'])
    encoding_type = data.get('encoding', 'none')
    scan_all_ports = data.get('scan_all_ports', True)

    if not targets:
        return jsonify({'error': 'No targets specified. Provide a list of targets.'}), 400

    if len(targets) > 50:
        return jsonify({'error': 'Maximum 50 targets allowed per scan.'}), 400

    scan_id = f"multi_{int(time.time())}"

    def run_multi_scan():
        all_results = {
            'scan_id': scan_id,
            'status': 'running',
            'total_targets': len(targets),
            'completed': 0,
            'targets': []
        }
        active_scans[scan_id] = all_results

        for idx, target in enumerate(targets):
            # Normalize target
            if not target.startswith(('http://', 'https://')):
                try:
                    socket.inet_aton(target)
                    target = f"http://{target}"
                except socket.error:
                    target = f"http://{target}"

            try:
                scanner = VulnerabilityScanner(target, scan_modules)
                scanner.scan_config['deep_scan'] = scan_all_ports
                scanner.scan()

                target_result = {
                    'target': target,
                    'status': 'completed',
                    'findings_count': len(scanner.findings),
                    'findings': scanner.findings,
                    'results': scanner.results
                }
                all_results['targets'].append(target_result)

            except Exception as e:
                all_results['targets'].append({
                    'target': target,
                    'status': 'failed',
                    'error': str(e)
                })

            all_results['completed'] = idx + 1

        all_results['status'] = 'completed'
        scan_results[scan_id] = all_results

    threading.Thread(target=run_multi_scan, daemon=True).start()

    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'total_targets': len(targets),
        'message': f'Scanning {len(targets)} targets...'
    })


@app.route('/api/scan/multi/<scan_id>', methods=['GET'])
def get_multi_scan_results(scan_id):
    """Get results of a multi-target scan."""
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    elif scan_id in active_scans:
        return jsonify(active_scans[scan_id])
    else:
        return jsonify({'error': 'Scan not found'}), 404


@app.route('/api/scan/multi/list', methods=['GET'])
def list_multi_scans():
    """List all multi-target scans."""
    scans = []
    for sid, result in {**active_scans, **scan_results}.items():
        if sid.startswith('multi_'):
            scans.append({
                'scan_id': sid,
                'status': result.get('status', 'unknown'),
                'total_targets': result.get('total_targets', 0),
                'completed': result.get('completed', 0)
            })
    return jsonify({'scans': scans})

if __name__ == '__main__':
    # Developer convenience only. The installed desktop app is launched through
    # desktop.py, which binds to loopback, requires a launch token and serves
    # the UI. This block is loopback-only and never runs the Flask debugger,
    # because the scanner can be aimed at arbitrary targets and should not be
    # reachable or debuggable from other machines.
    print("=" * 60)
    print("RED DRAGON - Advanced Vulnerability Scanner (development mode)")
    print("=" * 60)
    print("For the desktop application run:  python desktop.py")
    print("UI:  http://127.0.0.1:5000")
    print("API: http://127.0.0.1:5000/api/scan")
    print("=" * 60)
    app.run(
        host=os.environ.get('RED_DRAGON_HOST', '127.0.0.1'),
        port=int(os.environ.get('RED_DRAGON_PORT', '5000')),
        debug=False,
        threaded=True,
        use_reloader=False,
    )