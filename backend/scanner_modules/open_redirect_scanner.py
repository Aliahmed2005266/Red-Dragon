"""
Open Redirect Scanner Module
"""

import re
import requests
from scanner_modules.url_utils import with_param
from urllib.parse import urlparse, urljoin

class OpenRedirectScanner:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        
        # Open redirect test payloads
        self.redirect_payloads = [
            "//evil.com",
            "//evil.com/",
            "https://evil.com",
            "http://evil.com",
            "//evil.com%2f",
            "//evil.com%2f%2e%2e",
            "//evil.com/..",
            "//evil.com\\@",
            "http://evil.com:80",
            "https://evil.com:443",
            "//evil.com%23",
            "//evil.com%00",
            "//evil.com%0d%0a",
            "https://evil.com.evil.com",
            "http://evil.com%2eevil.com",
            "\\evil.com",
            "/\\evil.com",
            "//evil.com@",
            "https://evil.com?",
            "https://evil.com#",
            "//evil.com/?",
            "//evil.com/#",
            "%2f%2fevil.com",
            "%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d",
            "\\u0068\\u0074\\u0074\\u0070\\u0073\\u003a\\u002f\\u002f\\u0065\\u0076\\u0069\\u006c\\u002e\\u0063\\u006f\\u006d",
        ]

    def find_redirect_parameters(self):
        """Find potential redirect parameters in the page"""
        redirect_params = [
            'url', 'redirect', 'redirect_uri', 'redirect_url',
            'return', 'return_to', 'return_url', 'return_uri',
            'next', 'next_page', 'target', 'destination',
            'dest', 'continue', 'continue_url', 'forward',
            'forward_url', 'out', 'view', 'dir', 'file',
            'path', 'ref', 'referer', 'location',
            'link', 'href', 'to', 'login_redirect',
            'logout_redirect', 'callback', 'cb', 'image_url',
            'image', 'img', 'logo', 'profile_pic',
            'avatar', 'page', 'site', 'from',
        ]
        
        try:
            response = self.session.get(self.base_url, timeout=10)
            
            # Find parameters in the HTML
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            found_params = []
            
            # Check forms
            for form in soup.find_all('form'):
                for input_field in form.find_all(['input', 'textarea']):
                    name = input_field.get('name', '').lower()
                    if name in redirect_params:
                        found_params.append(name)
                        
                # Check action URL
                action = form.get('action', '').lower()
                href = form.get('href', '').lower()
                for param in redirect_params:
                    if param in action or param in href:
                        found_params.append(param)
            
            # Check links
            for link in soup.find_all('a', href=True):
                href = link.get('href', '').lower()
                for param in redirect_params:
                    if f'{param}=' in href:
                        found_params.append(param)
            
            # Check URL parameters
            parsed = urlparse(self.base_url)
            if parsed.query:
                from urllib.parse import parse_qs
                params = parse_qs(parsed.query)
                for param in params:
                    if param.lower() in redirect_params:
                        found_params.append(param.lower())
            
            # Check script content
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    for param in redirect_params:
                        if param in script.string.lower():
                            found_params.append(param)
            
            return list(set(found_params))
            
        except Exception as e:
            print(f"Redirect parameter detection error: {e}")
            return ['url', 'redirect', 'next']  # Fallback to common params

    def test_redirect(self, url, param_name):
        """Test a single parameter for open redirect"""
        findings = []
        
        for payload in self.redirect_payloads:
            try:
                # Inject payload into parameter
                test_url = url.replace(f"{param_name}=", f"{param_name}={payload}")
                
                response = self.session.get(test_url, timeout=10, allow_redirects=False)
                
                # Check for redirect
                if response.status_code in [301, 302, 303, 307, 308]:
                    redirect_location = response.headers.get('Location', '')
                    
                    # Check if redirect goes to external domain
                    if 'evil.com' in redirect_location:
                        findings.append({
                            'type': 'Open Redirect',
                            'severity': 'High',
                            'title': f'Open Redirect vulnerability in {param_name}',
                            'description': f'Parameter "{param_name}" is vulnerable to open redirect. An attacker can redirect users to arbitrary external websites.',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'redirect_url': redirect_location,
                            'remediation': 'Validate and whitelist redirect URLs. Do not redirect based on user input. Use internal URL mapping instead of passing URLs as parameters.'
                        })
                        break
                
                # Check for redirect in meta tags
                if 'evil.com' in response.text:
                    if 'refresh' in response.text.lower() and 'url=' in response.text.lower():
                        findings.append({
                            'type': 'Open Redirect',
                            'severity': 'High',
                            'title': f'Meta-refresh based open redirect in {param_name}',
                            'description': f'Parameter "{param_name}" is vulnerable to open redirect via meta refresh tag.',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'remediation': 'Avoid using meta refresh for redirects. Validate all redirect destinations.'
                        })
                        break
                        
                # Check for JavaScript redirects
                js_redirect_patterns = [
                    r'window\.location\s*=\s*["\'](?:https?:)?//evil\.com',
                    r'window\.location\.href\s*=\s*["\'](?:https?:)?//evil\.com',
                    r'document\.location\s*=\s*["\'](?:https?:)?//evil\.com',
                    r'document\.location\.href\s*=\s*["\'](?:https?:)?//evil\.com',
                ]
                
                for pattern in js_redirect_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        findings.append({
                            'type': 'Open Redirect',
                            'severity': 'High',
                            'title': f'JavaScript-based open redirect in {param_name}',
                            'description': f'Parameter "{param_name}" is vulnerable to open redirect via JavaScript.',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'remediation': 'Avoid using user input in JavaScript redirects. Use server-side validation.'
                        })
                        break
                        
            except Exception as e:
                continue
        
        return findings

    def test_header_injection_redirect(self):
        """Test for header injection that can cause redirects"""
        findings = []
        
        try:
            # CRLF injection test
            payloads = [
                "%0d%0aLocation:%20https://evil.com",
                "%0d%0aLocation:%20//evil.com",
                "\r\nLocation: https://evil.com",
                "%0aLocation:%20https://evil.com",
            ]
            
            for payload in payloads:
                test_url = with_param(self.base_url, "test", payload)
                response = self.session.get(test_url, timeout=10, allow_redirects=False)
                
                if 'evil.com' in str(response.headers).lower():
                    findings.append({
                        'type': 'Open Redirect',
                        'severity': 'Critical',
                        'title': 'CRLF Injection leading to open redirect',
                        'description': 'Header injection vulnerability allows injecting redirect headers via CRLF injection.',
                        'url': test_url,
                        'payload': payload,
                        'remediation': 'Sanitize all input that goes into response headers. Remove CRLF characters.'
                    })
                    break
                    
        except Exception as e:
            pass
        
        return findings

    def scan(self):
        """Main scanning function"""
        try:
            # Find redirect parameters
            redirect_params = self.find_redirect_parameters()
            
            # Test each found parameter
            for param in redirect_params:
                test_url = with_param(self.base_url, param, "https://google.com")
                results = self.test_redirect(test_url, param)
                self.findings.extend(results)
            
            # Test with common parameters if none found
            if not redirect_params:
                common_params = ['url', 'redirect', 'next', 'return', 'target', 'dest', 'goto']
                for param in common_params:
                    test_url = with_param(self.base_url, param, "https://google.com")
                    results = self.test_redirect(test_url, param)
                    self.findings.extend(results)
            
            # Test header injection redirects
            header_findings = self.test_header_injection_redirect()
            self.findings.extend(header_findings)
            
            # Test form action injection
            try:
                response = self.session.get(self.base_url, timeout=10)
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                
                forms = soup.find_all('form')
                for form in forms:
                    action = form.get('action', '')
                    if action and action != '#':
                        # Test if form action can be rewritten
                        for payload in ['//evil.com', 'https://evil.com']:
                            test_url = self.base_url.replace(action, payload) if action in self.base_url else None
                            if test_url:
                                resp = self.session.get(test_url, timeout=10, allow_redirects=False)
                                if resp.status_code in [301, 302, 303, 307, 308]:
                                    self.findings.append({
                                        'type': 'Open Redirect',
                                        'severity': 'High',
                                        'title': 'Form action URL injection',
                                        'description': 'Form action can be manipulated to redirect to external domains.',
                                        'url': self.base_url,
                                        'remediation': 'Validate form actions. Do not allow user-controlled action URLs.'
                                    })
                                    break
            except:
                pass
            
        except Exception as e:
            print(f"Open redirect scanning error: {e}")
        
        return self.findings
