"""
SSRF (Server-Side Request Forgery) Scanner Module
Tests for vulnerabilities where an attacker can induce the server
to make HTTP requests to internal or external resources.
"""
import re
import time
import requests
from scanner_modules.url_utils import with_param
from urllib.parse import urlparse, urljoin, parse_qs, urlencode


class SSRFScanner:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        self.internal_targets = [
            "http://127.0.0.1/", "http://127.0.0.1:80/", "http://127.0.0.1:8080/",
            "http://localhost/", "http://localhost:80/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://0x7f000001/", "http://2130706433/",
            "file:///etc/passwd", "file:///C:/windows/win.ini",
            "dict://127.0.0.1:6379/info",
        ]
        self.success_patterns = [
            r"root:.*:0:0:", r"\\[boot loader\\]", r"inet addr",
            r"ami-id", r"instance-id", r"computeMetadata", r"IDENTITY",
        ]
        self.ssrf_params = [
            "url", "uri", "link", "src", "target", "redirect",
            "redirect_url", "return_url", "next", "dest", "destination",
            "continue", "goto", "callback", "feed", "host", "file",
            "path", "template", "page", "name", "domain", "site",
        ]


    def test_parameter(self, url, param_name, method='GET'):
        """Test a single parameter for SSRF"""
        findings = []
        for target in self.internal_targets:
            try:
                if method == 'GET':
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = target
                    test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                    response = self.session.get(test_url, timeout=10, allow_redirects=False)
                else:
                    response = self.session.post(url, data={param_name: target}, timeout=10, allow_redirects=False)
                for pattern in self.success_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        findings.append({
                            'type': 'SSRF', 'severity': 'Critical',
                            'title': 'Server-Side Request Forgery (SSRF) detected',
                            'description': f'SSRF vulnerability in parameter "{param_name}". Server accessed: {target}',
                            'url': url, 'parameter': param_name, 'payload': target,
                            'evidence': f'Pattern matched: {pattern}',
                            'remediation': 'Validate and sanitize all user-supplied URLs. Use an allowlist of permitted domains.'
                        })
                        return findings
                if response.status_code == 200 and len(response.text) > 0:
                    try:
                        if method == 'GET':
                            baseline = self.session.get(url, timeout=5, allow_redirects=False)
                        else:
                            baseline = self.session.post(url, data={}, timeout=5, allow_redirects=False)
                        if abs(len(response.text) - len(baseline.text)) > 200:
                            findings.append({
                                'type': 'SSRF', 'severity': 'Medium',
                                'title': 'Possible SSRF (Response difference)',
                                'description': f'Possible SSRF in parameter "{param_name}". Response differs from baseline.',
                                'url': url, 'parameter': param_name, 'payload': target,
                                'remediation': 'Validate and sanitize all user-supplied URLs.'
                            })
                            return findings
                    except Exception:
                        pass
            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue
        return findings



    def test_url_fetch_endpoints(self):
        """Test common URL-fetching endpoints for SSRF"""
        findings = []
        common_endpoints = ["/fetch", "/proxy", "/download", "/redirect", "/url",
            "/api/fetch", "/api/proxy", "/api/redirect", "/image", "/avatar", "/webhook", "/preview"]
        test_internal = "http://169.254.169.254/latest/meta-data/"
        for endpoint in common_endpoints:
            test_url = f"{self.base_url}{endpoint}"
            try:
                response = self.session.get(test_url, params={"url": test_internal}, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    for pattern in self.success_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            findings.append({
                                'type': 'SSRF', 'severity': 'Critical',
                                'title': f'SSRF in endpoint {endpoint}',
                                'description': f'Endpoint {endpoint} accepts arbitrary URLs and returns content.',
                                'url': test_url, 'parameter': 'url', 'payload': test_internal,
                                'remediation': 'Restrict URL fetching to allowed domains. Disable dangerous URL schemes.'
                            })
                            break
            except Exception:
                continue
        return findings

    def scan(self):
        """Main scanning function"""
        try:
            response = self.session.get(self.base_url, timeout=10)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').upper()
                form_url = action if action.startswith('http') else (urljoin(self.base_url, action) if action else self.base_url)
                for inp in form.find_all(['input', 'textarea']):
                    pn = inp.get('name')
                    if pn and any(p in pn.lower() for p in self.ssrf_params):
                        self.findings.extend(self.test_parameter(form_url, pn, method))
            parsed = urlparse(self.base_url)
            if parsed.query:
                for pn in parse_qs(parsed.query).keys():
                    if any(p in pn.lower() for p in self.ssrf_params):
                        self.findings.extend(self.test_parameter(self.base_url, pn))
            for param in self.ssrf_params:
                self.findings.extend(self.test_parameter(with_param(self.base_url, param, "http://example.com"), param))
            self.findings.extend(self.test_url_fetch_endpoints())
        except Exception as e:
            print(f"SSRF scanning error: {e}")
        return self.findings

