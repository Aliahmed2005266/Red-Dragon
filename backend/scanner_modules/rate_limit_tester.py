"""
Rate Limit Tester Module
"""

import time
import requests
from urllib.parse import urlparse

class RateLimitTester:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        
    def test_rate_limits(self):
        """Test if rate limiting is in place"""
        results = {
            'rate_limited': False,
            'threshold': None,
            'requests_before_limit': 0,
            'status_code': None
        }
        
        try:
            # Send rapid requests
            for i in range(100):
                response = self.session.get(self.base_url, timeout=5)
                
                if response.status_code == 429:  # Too Many Requests
                    results['rate_limited'] = True
                    results['threshold'] = i + 1
                    results['requests_before_limit'] = i
                    results['status_code'] = 429
                    break
                    
        except Exception as e:
            print(f"Rate limit testing error: {e}")
        
        return results
    
    def test_login_rate_limit(self):
        """Test rate limiting on login endpoints"""
        results = {
            'login_rate_limited': False,
            'threshold': None,
        }
        
        login_paths = [
            '/login',
            '/wp-login.php',
            '/api/login',
            '/api/auth/login',
            '/signin',
            '/auth',
        ]
        
        for path in login_paths:
            test_url = f"{self.base_url}{path}"
            try:
                # Send rapid login attempts
                for i in range(20):
                    response = self.session.post(test_url, data={'username': 'test', 'password': 'test'}, timeout=5)
                    
                    if response.status_code == 429:
                        results['login_rate_limited'] = True
                        results['threshold'] = i + 1
                        return results
            except:
                continue
        
        return results

    def test_api_rate_limit(self):
        """Test rate limiting on API endpoints"""
        results = {
            'api_rate_limited': False,
            'threshold': None,
        }
        
        api_paths = [
            '/api',
            '/api/v1',
            '/graphql',
            '/users',
            '/data',
        ]
        
        for path in api_paths:
            test_url = f"{self.base_url}{path}"
            try:
                # Send rapid requests
                for i in range(30):
                    response = self.session.get(test_url, timeout=5)
                    
                    if response.status_code == 429:
                        results['api_rate_limited'] = True
                        results['threshold'] = i + 1
                        return results
            except:
                continue
        
        return results

    def scan(self):
        """Main scanning function"""
        # Test general rate limits
        general_results = self.test_rate_limits()
        
        if general_results['rate_limited']:
            self.findings.append({
                'type': 'Rate Limiting',
                'severity': 'Good',
                'title': 'Rate limiting is implemented',
                'description': f'Rate limiting detected after {general_results["requests_before_limit"]} requests.',
                'url': self.base_url,
                'threshold': general_results['threshold'],
                'remediation': 'Rate limiting is properly configured.'
            })
        else:
            self.findings.append({
                'type': 'Rate Limiting',
                'severity': 'Medium',
                'title': 'No rate limiting detected',
                'description': 'No rate limiting detected on the main application. This could allow brute force attacks.',
                'url': self.base_url,
                'remediation': 'Implement rate limiting to prevent brute force attacks and DoS.'
            })
        
        # Test login rate limits
        login_results = self.test_login_rate_limit()
        
        if not login_results['login_rate_limited']:
            self.findings.append({
                'type': 'Rate Limiting',
                'severity': 'High',
                'title': 'Login rate limiting not implemented',
                'description': 'Login endpoints do not have rate limiting. Vulnerable to brute force attacks.',
                'url': self.base_url,
                'remediation': 'Implement rate limiting on login endpoints. Use account lockout policies.'
            })
        
        # Test API rate limits
        api_results = self.test_api_rate_limit()
        
        if not api_results['api_rate_limited']:
            self.findings.append({
                'type': 'Rate Limiting',
                'severity': 'Medium',
                'title': 'API rate limiting not implemented',
                'description': 'API endpoints do not have rate limiting. Vulnerable to abuse.',
                'url': self.base_url,
                'remediation': 'Implement API rate limiting using token bucket or sliding window algorithms.'
            })
        
        return self.findings