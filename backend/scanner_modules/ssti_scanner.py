"""
SSTI (Server-Side Template Injection) Scanner Module
Tests for vulnerabilities where user input is embedded in server-side
templates (Jinja2, Twig, Freemarker, Velocity, etc.) allowing
server-side code execution.
"""
import re
import requests
from scanner_modules.url_utils import with_param
from urllib.parse import urlparse, urljoin, parse_qs, urlencode


class SSTIScanner:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        self.math_tests = [
            ("{{7*7}}", "49"),
            ("${{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("#set($x=7*7)${{x}}", "49"),
        ]
        self.reflect_tests = [
            ("{{config}}", ["Config", "config"]),
            ("{{''.__class__}}", ["class", "<class"]),
            ("${{T(java.lang.Runtime)}}", ["Runtime", "java.lang"]),
        ]
        self.ssti_params = [
            "name", "username", "title", "message", "content", "text",
            "query", "search", "q", "keyword", "term", "input",
            "template", "view", "page", "layout", "skin", "theme",
            "greeting", "welcome", "comment", "description", "body",
        ]

    def test_parameter(self, url, param_name, method='GET'):
        """Test a single parameter for SSTI"""
        findings = []
        try:
            if method == 'GET':
                baseline = self.session.get(url, timeout=10)
            else:
                baseline = self.session.post(url, data={}, timeout=10)
            baseline_text = baseline.text
        except Exception:
            return findings
        for payload, expected in self.math_tests:
            try:
                if method == 'GET':
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = payload
                    test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                    response = self.session.get(test_url, timeout=10)
                else:
                    response = self.session.post(url, data={param_name: payload}, timeout=10)
                if expected in response.text and expected not in baseline_text:
                    findings.append({
                        'type': 'SSTI', 'severity': 'Critical',
                        'title': 'Server-Side Template Injection (SSTI) detected',
                        'description': f'SSTI in parameter "{param_name}". Expression evaluated.',
                        'url': url, 'parameter': param_name, 'payload': payload,
                        'evidence': f'Expected "{expected}" found in response',
                        'remediation': 'Never embed user input directly in templates. Use sandboxed engines.'
                    })
                    return findings
                for err_pat in [r"jinja2", r"TemplateSyntaxError", r"Smarty",
                                r"Twig", r"freemarker", r"Velocity", r"Thymeleaf", r"Mako"]:
                    if re.search(err_pat, response.text, re.IGNORECASE) and err_pat.lower() not in baseline_text.lower():
                        findings.append({
                            'type': 'SSTI', 'severity': 'High',
                            'title': 'Possible SSTI (Template engine error)',
                            'description': f'Template engine error in response for parameter "{param_name}".',
                            'url': url, 'parameter': param_name, 'payload': payload,
                            'evidence': f'Error pattern: {err_pat}',
                            'remediation': 'Never embed user input in templates. Use sandboxed engines.'
                        })
                        return findings
            except Exception:
                continue
        for payload, indicators in self.reflect_tests:
            try:
                if method == 'GET':
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = payload
                    test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                    response = self.session.get(test_url, timeout=10)
                else:
                    response = self.session.post(url, data={param_name: payload}, timeout=10)
                for indicator in indicators:
                    if indicator in response.text and indicator not in baseline_text:
                        findings.append({
                            'type': 'SSTI', 'severity': 'Critical',
                            'title': 'Server-Side Template Injection (SSTI) detected',
                            'description': f'SSTI in parameter "{param_name}". Template evaluation reflected.',
                            'url': url, 'parameter': param_name, 'payload': payload,
                            'evidence': f'Reflected indicator: {indicator}',
                            'remediation': 'Never embed user input in templates. Use sandboxed engines.'
                        })
                        return findings
            except Exception:
                continue
        return findings

    def test_url_for_ssti(self):
        """Test URL path for SSTI"""
        findings = []
        parsed = urlparse(self.base_url)
        path_parts = parsed.path.strip('/').split('/')
        if path_parts and path_parts[0]:
            for payload in ["{{7*7}}", "${{7*7}}"]:
                for part in path_parts:
                    test_path = parsed.path.replace(part, payload)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"
                    try:
                        response = self.session.get(test_url, timeout=5)
                        if "49" in response.text:
                            findings.append({
                                'type': 'SSTI', 'severity': 'Critical',
                                'title': 'SSTI in URL path',
                                'description': 'URL path segment processed by template engine.',
                                'url': test_url, 'payload': payload,
                                'remediation': 'Never embed user input directly in templates.'
                            })
                            return findings
                    except Exception:
                        continue
        return findings
        parsed = urlparse(self.base_url)
        path_parts = parsed.path.strip('/').split('/')
        if path_parts and path_parts[0]:
            for payload in ["{{7*7}}", "${{7*7}}"]:
                for part in path_parts:
                    test_path = parsed.path.replace(part, payload)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"
                    try:
                        response = self.session.get(test_url, timeout=5)
                        if "49" in response.text:
                            findings.append({
                                'type': 'SSTI', 'severity': 'Critical',
                                'title': 'SSTI in URL path',
                                'description': 'URL path segment processed by template engine.',
                                'url': test_url, 'payload': payload,
                                'remediation': 'Never embed user input directly in templates.'
                            })
                            return findings
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
                    param_name = inp.get('name')
                    if param_name:
                        self.findings.extend(self.test_parameter(form_url, param_name, method))
            parsed = urlparse(self.base_url)
            if parsed.query:
                for param_name in parse_qs(parsed.query).keys():
                    self.findings.extend(self.test_parameter(self.base_url, param_name))
            for param in self.ssti_params:
                self.findings.extend(self.test_parameter(with_param(self.base_url, param, "test"), param))
            self.findings.extend(self.test_url_for_ssti())
        except Exception as e:
            print(f"SSTI scanning error: {e}")
        return self.findings

