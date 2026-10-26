"""
XSS Scanner Module
"""

import re
import requests
from scanner_modules.url_utils import with_param
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

class XSSScanner:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        
        # XSS payloads (deduplicated)
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert('XSS')>",
            "<svg onload=alert(1)>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<video src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<script/src=//example.com/xss.js></script>",
            "\"'><script>alert('XSS')</script>",
            "<script>alert(document.cookie)</script>",
            "'\"><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><img src=x onerror=alert('XSS')>",
            "\"><img src=x onerror=alert('XSS')>",
            "<ScRiPt>alert('XSS')</sCrIpT>",
            "<SCRIPT>alert('XSS')</SCRIPT>",
            "<script>/*<![CDATA[*/alert('XSS');/*]]>*/</script>",
            "<script>/**/alert('XSS');</script>",
            "<script>0;alert('XSS');</script>",
            "<script>;alert('XSS');</script>",
            "<script>alert('XSS')//</script>",
            "data:text/html,<script>alert('XSS')</script>",
            "data:text/html;base64,PHN2ZyBvbmVycm9yPSJhbGVydCgnWFNTJyk+PC9zdmc+",
        ]
        
        # Detection patterns
        self.detection_patterns = [
            r"<script>alert\('XSS'\)</script>",
            r"onerror=alert\(",
            r"onload=alert\(",
            r"onfocus=alert\(",
            r"onmouseover=alert\(",
            r"onclick=alert\(",
            r"javascript:alert\(",
        ]

    def test_parameter(self, url, param_name, method='GET'):
        """Test a parameter for XSS vulnerability"""
        findings = []
        
        try:
            # Get base response
            if method == 'GET':
                base_response = self.session.get(url, timeout=10)
            else:
                base_response = self.session.post(url, data={}, timeout=10)
            base_length = len(base_response.text)
        except:
            return findings
        
        # Test payloads
        for payload in self.xss_payloads:
            try:
                if method == 'GET':
                    test_url = url.replace(f"{param_name}=", f"{param_name}={payload}")
                    response = self.session.get(test_url, timeout=10)
                else:
                    response = self.session.post(url, data={param_name: payload}, timeout=10)
                
                # Check if payload is reflected
                if payload in response.text:
                    findings.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'title': f'Reflected XSS vulnerability detected',
                        'description': f'Parameter "{param_name}" is vulnerable to reflected XSS. User input is reflected without proper encoding.',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'remediation': 'Implement proper output encoding when reflecting user input. Use Content Security Policy (CSP) headers. Sanitize and validate all user inputs.'
                    })
                    return findings  # Stop testing this parameter
                
                # Check for pattern matches
                for pattern in self.detection_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        findings.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'High',
                            'title': f'Possible XSS vulnerability (Pattern-based)',
                            'description': f'XSS vulnerability detected in parameter "{param_name}" through pattern matching.',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'Pattern matched: {pattern}',
                            'remediation': 'Implement proper output encoding. Use context-aware escaping. Apply Content Security Policy.'
                        })
                        return findings  # Stop testing this parameter
                        
            except Exception as e:
                continue
        
        return findings

    def scan(self):
        """Main scanning function"""
        try:
            # Get initial page
            response = self.session.get(self.base_url, timeout=10)
            
            # Find all forms
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all forms
            forms = soup.find_all('form')
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').upper()
                
                # Resolve URL
                if action:
                    if action.startswith('http'):
                        form_url = action
                    else:
                        form_url = urljoin(self.base_url, action)
                else:
                    form_url = self.base_url
                
                # Get all input fields
                inputs = form.find_all(['input', 'textarea'])
                
                for input_field in inputs:
                    param_name = input_field.get('name')
                    if param_name:
                        # Test parameter
                        results = self.test_parameter(form_url, param_name, method)
                        self.findings.extend(results)
            
            # Test URL parameters
            parsed = urlparse(self.base_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param_name in params.keys():
                    results = self.test_parameter(self.base_url, param_name)
                    self.findings.extend(results)
            
            # Test common parameters
            common_params = ['search', 'q', 'query', 'name', 'message', 'comment', 'text', 'input']
            for param in common_params:
                test_url = with_param(self.base_url, param, "test")
                results = self.test_parameter(test_url, param)
                self.findings.extend(results)
            
        except Exception as e:
            print(f"XSS scanning error: {e}")
        
        return self.findings
