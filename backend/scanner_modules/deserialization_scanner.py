"""
Insecure Deserialization Scanner Module
Tests for vulnerabilities where untrusted data is deserialized
on the server, potentially leading to remote code execution.
Covers: Python pickle, Java serialization, PHP object injection,
Node.js deserialization.
"""
import re
import base64
import requests
from scanner_modules.url_utils import with_param
from urllib.parse import urlparse, urljoin, parse_qs, urlencode


class DeserializationScanner:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        self.python_payloads = [
            "gASVKAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwMb3MuZ2V0ZW52KCmUhZRSlIwY=",
            "KGRwMApTJ3Rlc3QnCnAxClMndGVzdCcKcDIKcy4=",
        ]
        self.php_payloads = [
            'O:8:"stdClass":1:{s:4:"test";s:5:"value";}',
            'O:1:"a":1:{s:4:"test";s:3:"cmd";}',
            'a:1:{s:4:"test";s:5:"value";}',
            'O:11:"TypeChanger":3:{s:4:"type";s:4:"exec";s:5:"value";s:2:"id";s:5:"param";s:2:"id";}',
        ]
        self.node_payloads = [
            '{"__proto__":{"polluted":"test"}}',
            '{"constructor":{"prototype":{"polluted":"test"}}}',
        ]
        self.deser_params = [
            "data", "object", "serialized", "payload", "input",
            "json", "xml", "state", "session", "token", "auth",
            "user", "config", "settings", "cache", "file",
            "content", "body", "request", "response", "form",
            "cookie", "PHPSESSID", "session_id", "sid",
            "viewstate", "__VIEWSTATE",
        ]
        self.error_patterns = [
            r"pickle", r"unpickle", r"deserializ", r"ObjectInputStream",
            r"readObject", r"unserialize", r"__PHP_Incomplete_Class",
            r"__wakeup", r"__destruct", r"__toString", r"__call",
            r"__get", r"__set", r"__isset", r"__unset",
            r"InvocationTargetException", r"ClassNotFoundException",
            r"InvalidClassException", r"StreamCorruptedException",
            r"OptionalDataException", r"SerializationException",
            r"FormatException", r"LosFormatter", r"BinaryFormatter",
            r"ObjectStateFormatter", r"JavaScriptSerializer",
        ]


    def test_parameter(self, url, param_name, method='GET'):
        """Test a single parameter for insecure deserialization"""
        findings = []
        for payload in self.python_payloads:
            try:
                if method == 'GET':
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = payload
                    test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                    response = self.session.get(test_url, timeout=10)
                else:
                    response = self.session.post(url, data={param_name: payload}, timeout=10)
                for pattern in self.error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        findings.append({
                            'type': 'Insecure Deserialization', 'severity': 'Critical',
                            'title': 'Insecure Deserialization (Python pickle)',
                            'description': f'Parameter "{param_name}" processes serialized Python objects.',
                            'url': url, 'parameter': param_name, 'payload': payload[:100],
                            'evidence': f'Error pattern: {pattern}',
                            'remediation': 'Never deserialize untrusted data with pickle. Use JSON.'
                        })
                        return findings
            except Exception:
                continue
        for payload in self.php_payloads:
            try:
                if method == 'GET':
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = payload
                    test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                    response = self.session.get(test_url, timeout=10)
                else:
                    response = self.session.post(url, data={param_name: payload}, timeout=10)
                for pattern in self.error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        findings.append({
                            'type': 'Insecure Deserialization', 'severity': 'Critical',
                            'title': 'Insecure Deserialization (PHP)',
                            'description': f'Parameter "{param_name}" processes PHP serialized data.',
                            'url': url, 'parameter': param_name, 'payload': payload[:100],
                            'evidence': f'Error pattern: {pattern}',
                            'remediation': 'Never unserialize untrusted data. Use json_encode/decode.'
                        })
                        return findings
            except Exception:
                continue
        for payload in self.node_payloads:
            try:
                if method == 'GET':
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = payload
                    test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                    response = self.session.get(test_url, timeout=10)
                else:
                    response = self.session.post(url, data={param_name: payload}, timeout=10)
                for pattern in self.error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        findings.append({
                            'type': 'Insecure Deserialization', 'severity': 'Critical',
                            'title': 'Insecure Deserialization (Node.js)',
                            'description': f'Parameter "{param_name}" processes serialized JS objects.',
                            'url': url, 'parameter': param_name, 'payload': payload[:100],
                            'evidence': f'Error pattern: {pattern}',
                            'remediation': 'Never use node-serialize on untrusted data. Use JSON.parse.'
                        })
                        return findings
            except Exception:
                continue
        return findings

    def test_cookies_for_deserialization(self):
        """Test cookies for insecure deserialization"""
        findings = []
        try:
            response = self.session.get(self.base_url, timeout=10)
            for cookie in response.cookies:
                cookie_value = cookie.value
                try:
                    decoded = base64.b64decode(cookie_value)
                    if decoded.startswith(b'\x80') or b'pickle' in decoded.lower():
                        findings.append({
                            'type': 'Insecure Deserialization', 'severity': 'High',
                            'title': f'Possible serialized cookie: {cookie.name}',
                            'description': f'Cookie "{cookie.name}" contains serialized Python data.',
                            'url': self.base_url, 'parameter': cookie.name,
                            'evidence': f'Decoded starts with: {decoded[:20]}',
                            'remediation': 'Do not store serialized objects in cookies.'
                        })
                    if decoded.startswith(b'\xac\xed\x00\x05'):
                        findings.append({
                            'type': 'Insecure Deserialization', 'severity': 'High',
                            'title': f'Java serialized cookie: {cookie.name}',
                            'description': f'Cookie "{cookie.name}" contains Java serialized object.',
                            'url': self.base_url, 'parameter': cookie.name,
                            'evidence': 'Java serialization magic bytes detected',
                            'remediation': 'Do not store serialized objects in cookies.'
                        })
                except Exception:
                    pass
                if re.match(r'^[aO]:\d+:', cookie_value):
                    findings.append({
                        'type': 'Insecure Deserialization', 'severity': 'High',
                        'title': f'PHP serialized cookie: {cookie.name}',
                        'description': f'Cookie "{cookie.name}" contains PHP serialized data.',
                        'url': self.base_url, 'parameter': cookie.name,
                        'evidence': 'PHP serialization format detected',
                        'remediation': 'Do not store serialized objects in cookies.'
                    })
        except Exception:
            pass
        return findings





    def test_headers_for_deserialization(self):
        """Test HTTP headers for deserialization vulnerabilities"""
        findings = []
        test_headers = {
            'X-Session-Data': base64.b64encode(b'\x80\x03X\x04\x00\x00\x00testq\x00.').decode(),
            'X-User-Data': 'O:8:"stdClass":1:{s:4:"test";s:5:"value";}',
        }
        for header_name, header_value in test_headers.items():
            try:
                response = self.session.get(self.base_url, headers={header_name: header_value}, timeout=5)
                for pattern in self.error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        findings.append({
                            'type': 'Insecure Deserialization', 'severity': 'High',
                            'title': f'Deserialization via header: {header_name}',
                            'description': f'Header "{header_name}" appears to be deserialized.',
                            'url': self.base_url, 'parameter': header_name,
                            'payload': header_value[:100],
                            'evidence': f'Error pattern: {pattern}',
                            'remediation': 'Do not deserialize data from HTTP headers.'
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
                    param_name = inp.get('name')
                    if param_name and any(p in param_name.lower() for p in self.deser_params):
                        self.findings.extend(self.test_parameter(form_url, param_name, method))
            parsed = urlparse(self.base_url)
            if parsed.query:
                for param_name in parse_qs(parsed.query).keys():
                    if any(p in param_name.lower() for p in self.deser_params):
                        self.findings.extend(self.test_parameter(self.base_url, param_name))
            for param in self.deser_params:
                self.findings.extend(self.test_parameter(with_param(self.base_url, param, "test"), param))
            self.findings.extend(self.test_cookies_for_deserialization())
            self.findings.extend(self.test_headers_for_deserialization())
        except Exception as e:
            print(f"Deserialization scanning error: {e}")
        return self.findings

