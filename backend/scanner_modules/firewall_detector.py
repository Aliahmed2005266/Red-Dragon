"""
Firewall/WAF Detection Module
"""

import re
import requests
from scanner_modules.url_utils import with_param
from urllib.parse import urlparse

class FirewallDetector:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        
        # WAF signatures
        self.waf_signatures = {
            'Cloudflare': [
                'cloudflare',
                '__cfduid',
                'cf-ray',
                'cf-cache-status',
            ],
            'AWS WAF': [
                'x-amzn-waf',
                'AWS-WAF',
            ],
            'ModSecurity': [
                'mod_security',
                'modsecurity',
                'X-Mod-Security',
            ],
            'Wordfence': [
                'wordfence',
                'wf-blocked',
            ],
            'Imperva': [
                'imperva',
                'incap_ses',
                'incap_visid',
            ],
            'Akamai': [
                'akamai',
                'akamai-gtm',
            ],
            'F5 Big-IP': [
                'BIGIPSERVER',
                'big-ip',
                'F5',
            ],
            'Barracuda': [
                'barracuda',
                'barra_counter_session',
            ],
            'Sucuri': [
                'sucuri',
                'X-Sucuri',
            ],
        }
        
        # Firewall behaviors
        self.test_payloads = [
            "' OR '1'='1",
            "<script>alert('test')</script>",
            "../../../../etc/passwd",
            "UNION SELECT * FROM users--",
        ]

    def detect_waf(self):
        """Detect WAF/firewall"""
        try:
            response = self.session.get(self.base_url, timeout=10)
            headers = response.headers
            
            # Check headers for WAF signatures
            for waf_name, signatures in self.waf_signatures.items():
                for signature in signatures:
                    # Check response headers
                    header_str = str(dict(headers)).lower()
                    if signature.lower() in header_str:
                        return waf_name
            
            # Test with malicious payload and check for blocking
            for payload in self.test_payloads:
                try:
                    test_response = self.session.get(self.base_url, params={'test': payload}, timeout=5)
                    
                    if test_response.status_code in [403, 406, 419, 429]:
                        return 'Generic WAF/Firewall'
                    
                    # Check for WAF-specific blocking indicators
                    if any(indicator in test_response.text.lower() for indicator in 
                           ['blocked', 'forbidden', 'security', 'firewall', 'waf']):
                        return 'Generic WAF/Firewall'
                        
                except:
                    continue
                    
        except Exception as e:
            print(f"Firewall detection error: {e}")
        
        return None

    def test_bypass_techniques(self):
        """Test common WAF bypass techniques"""
        bypass_methods = {
            'case_variation': "' OR '1'='1",
            'double_encode': "%2527%20OR%25271%252D%252D",
            'comment_obfuscation': "'/**/OR/**/1/**/=/**/1",
            'whitespace_obfuscation': "'%0aOR%0a'1'%3d'1",
            'null_byte': "%00'%20OR%20'1'%3d'1",
        }
        
        results = []
        
        for method, payload in bypass_methods.items():
            try:
                test_url = with_param(self.base_url, "id", payload)
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    results.append({
                        'method': method,
                        'success': True
                    })
            except:
                continue
        
        return results

    def scan(self):
        """Main scanning function"""
        waf_detected = self.detect_waf()
        
        if waf_detected:
            bypass_techniques = self.test_bypass_techniques()
            
            result = {
                'type': 'Firewall',
                'severity': 'Info',
                'title': f'Firewall/WAF detected: {waf_detected}',
                'description': f'A firewall or WAF is protecting the application. WAF name: {waf_detected}',
                'bypass_techniques': bypass_techniques,
                'remediation': 'WAF provides protection but not bulletproof. Follow secure coding practices.'
            }
            
            if bypass_techniques:
                result['title'] = f'Potential WAF bypass detected'
                result['severity'] = 'High'
                result['description'] += ' WAF bypass techniques appear to be working.'
        else:
            result = {
                'type': 'Firewall',
                'severity': 'Info',
                'title': 'No WAF detected',
                'description': 'No Web Application Firewall was detected on the target.',
                'remediation': 'Consider implementing a WAF for additional protection.'
            }
        
        self.findings.append(result)
        return self.findings
