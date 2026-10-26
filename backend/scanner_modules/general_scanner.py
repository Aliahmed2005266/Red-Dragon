"""
General Information Scanner Module
"""

import re
import requests
from urllib.parse import urlparse, urljoin

class GeneralScanner:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        
    def detect_headers(self):
        """Analyze HTTP headers for security issues"""
        try:
            response = self.session.get(self.base_url, timeout=10)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'X-XSS-Protection': 'XSS filter',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content Security Policy',
                'Referrer-Policy': 'Referrer policy',
                'Permissions-Policy': 'Feature permissions',
            }
            
            missing_headers = []
            for header, description in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                self.findings.append({
                    'type': 'Configuration',
                    'severity': 'Medium',
                    'title': 'Missing security headers',
                    'description': f'Missing security headers: {", ".join(missing_headers)}',
                    'url': self.base_url,
                    'missing_headers': missing_headers,
                    'remediation': 'Implement recommended security headers to improve security posture.'
                })
            
            # Check for information disclosure headers
            if 'Server' in headers:
                server = headers['Server']
                if any(vendor in server for vendor in ['Apache', 'Nginx', 'IIS', 'Express']):
                    self.findings.append({
                        'type': 'Information Disclosure',
                        'severity': 'Low',
                        'title': 'Server header reveals technology',
                        'description': f'Server header discloses: {server}',
                        'url': self.base_url,
                        'remediation': 'Remove or obfuscate Server header to reduce information disclosure.'
                    })
            
            if 'X-Powered-By' in headers:
                powered_by = headers['X-Powered-By']
                self.findings.append({
                    'type': 'Information Disclosure',
                    'severity': 'Low',
                    'title': 'X-Powered-By header reveals technology',
                    'description': f'X-Powered-By header discloses: {powered_by}',
                    'url': self.base_url,
                    'remediation': 'Remove X-Powered-By header to reduce information disclosure.'
                })
                
        except Exception as e:
            print(f"Header analysis error: {e}")
    
    def detect_forms(self):
        """Detect forms and potential entry points"""
        try:
            response = self.session.get(self.base_url, timeout=10)
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            if forms:
                self.findings.append({
                    'type': 'Information',
                    'severity': 'Info',
                    'title': f'{len(forms)} form(s) detected',
                    'description': f'Found {len(forms)} forms on the page. These are potential injection points.',
                    'url': self.base_url,
                    'form_count': len(forms),
                    'remediation': 'Ensure all form inputs are properly validated and sanitized.'
                })
        except:
            pass
    
    def detect_comments(self):
        """Detect HTML comments with sensitive information"""
        try:
            response = self.session.get(self.base_url, timeout=10)
            
            # Look for HTML comments
            comments = re.findall(r'<!--(.+?)-->', response.text, re.DOTALL)
            
            for comment in comments:
                # Check for sensitive information
                if any(keyword in comment.lower() for keyword in 
                       ['password', 'secret', 'key', 'token', 'api', 'database', 'config']):
                    self.findings.append({
                        'type': 'Information Disclosure',
                        'severity': 'Medium',
                        'title': 'Sensitive information in HTML comments',
                        'description': f'HTML comment contains potentially sensitive information: {comment[:200]}',
                        'url': self.base_url,
                        'remediation': 'Remove sensitive information from HTML comments.'
                    })
                    break
        except:
            pass
    
    def detect_javascript_analyze(self):
        """Analyze JavaScript for potential vulnerabilities"""
        try:
            response = self.session.get(self.base_url, timeout=10)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            scripts = soup.find_all('script')
            js_files = []
            
            for script in scripts:
                src = script.get('src')
                if src:
                    if src.startswith('http'):
                        js_files.append(src)
                    else:
                        js_files.append(urljoin(self.base_url, src))
            
            if js_files:
                self.findings.append({
                    'type': 'Information',
                    'severity': 'Info',
                    'title': f'{len(js_files)} JavaScript file(s) detected',
                    'description': f'Found {len(js_files)} JavaScript files. Review for hardcoded secrets, API keys, and logic flaws.',
                    'url': self.base_url,
                    'js_files': js_files,
                    'remediation': 'Review JavaScript files for hardcoded secrets and vulnerabilities.'
                })
        except:
            pass
    
    def detect_cookies(self):
        """Analyze cookies for security issues"""
        try:
            response = self.session.get(self.base_url, timeout=10)
            
            if response.cookies:
                insecure_cookies = []
                for cookie in response.cookies:
                    issues = []
                    if not cookie.secure:
                        issues.append('not Secure')
                    if not cookie.has_nonstandard_attr('HttpOnly'):
                        issues.append('not HttpOnly')
                    if not cookie.has_nonstandard_attr('SameSite'):
                        issues.append('missing SameSite')
                    
                    if issues:
                        insecure_cookies.append({
                            'name': cookie.name,
                            'issues': issues
                        })
                
                if insecure_cookies:
                    self.findings.append({
                        'type': 'Configuration',
                        'severity': 'Medium',
                        'title': 'Insecure cookie configuration',
                        'description': f'{len(insecure_cookies)} cookie(s) with missing security flags detected.',
                        'url': self.base_url,
                        'insecure_cookies': insecure_cookies,
                        'remediation': 'Set Secure, HttpOnly, and SameSite flags on all cookies.'
                    })
        except:
            pass

    def scan(self):
        """Main scanning function"""
        try:
            self.detect_headers()
            self.detect_forms()
            self.detect_comments()
            self.detect_javascript_analyze()
            self.detect_cookies()
        except Exception as e:
            print(f"General scanning error: {e}")
        
        return self.findings