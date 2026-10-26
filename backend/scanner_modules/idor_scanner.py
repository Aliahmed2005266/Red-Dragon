"""
IDOR (Insecure Direct Object Reference) Scanner Module
"""

import re
import requests
from scanner_modules.url_utils import with_param
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

class IDORScanner:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        self.discovered_ids = []
        
    def extract_ids_from_url(self, url):
        """Extract potential IDs from URL parameters"""
        ids = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name, values in params.items():
            if values:
                value = values[0]
                # Check if value looks like an ID (numeric or UUID)
                if re.match(r'^\d+$', value):
                    ids.append({'param': param_name, 'value': value, 'type': 'numeric'})
                elif re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', value):
                    ids.append({'param': param_name, 'value': value, 'type': 'uuid'})
        
        return ids
    
    def test_idor(self, url, param_name, original_id):
        """Test for IDOR vulnerability"""
        findings = []
        
        try:
            # Get original response
            original_response = self.session.get(url, timeout=10)
            original_status = original_response.status_code
            original_length = len(original_response.text)
            
            # Test with modified IDs
            test_ids = self.generate_test_ids(original_id)
            
            for test_id in test_ids:
                try:
                    # Replace ID in URL
                    test_url = url.replace(f"{param_name}={original_id}", f"{param_name}={test_id}")
                    
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check if we can access different object
                    if response.status_code == 200:
                        if abs(len(response.text) - original_length) > 50:
                            findings.append({
                                'type': 'Insecure Direct Object Reference (IDOR)',
                                'severity': 'High',
                                'title': f'IDOR vulnerability in parameter {param_name}',
                                'description': f'Parameter "{param_name}" appears to be vulnerable to IDOR. Access to unauthorized objects may be possible.',
                                'url': url,
                                'parameter': param_name,
                                'original_id': original_id,
                                'tested_id': test_id,
                                'remediation': 'Implement proper access controls. Verify user permissions before returning objects. Use indirect references instead of direct database IDs.'
                            })
                            break
                            
                except Exception as e:
                    continue
                    
        except Exception as e:
            pass
        
        return findings
    
    def generate_test_ids(self, original_id):
        """Generate test IDs for IDOR testing"""
        test_ids = []
        
        try:
            # Test similar IDs
            if original_id.isdigit():
                num_id = int(original_id)
                test_ids.extend([
                    str(num_id - 1),
                    str(num_id + 1),
                    str(num_id + 100),
                    str(1),
                    str(2),
                    '1',
                    '2'
                ])
        except:
            pass
        
        return test_ids
    
    def scan(self):
        """Main scanning function"""
        try:
            # Get initial page
            response = self.session.get(self.base_url, timeout=10)
            
            # Find all links
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            links = soup.find_all('a', href=True)
            forms = soup.find_all('form')
            
            # Extract IDs from links
            for link in links:
                href = link.get('href')
                if href:
                    if href.startswith('http'):
                        full_url = href
                    else:
                        full_url = urljoin(self.base_url, href)
                    
                    ids = self.extract_ids_from_url(full_url)
                    if ids:
                        for id_info in ids:
                            findings = self.test_idor(full_url, id_info['param'], id_info['value'])
                            self.findings.extend(findings)
            
            # Extract IDs from forms
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
                
                inputs = form.find_all(['input', 'select'])
                for input_field in inputs:
                    param_name = input_field.get('name')
                    if param_name and ('id' in param_name.lower() or 'user' in param_name.lower()):
                        test_url = with_param(form_url, param_name, "1") if method == 'GET' else form_url
                        findings = self.test_idor(test_url, param_name, '1')
                        self.findings.extend(findings)
            
            # Test current URL
            ids = self.extract_ids_from_url(self.base_url)
            for id_info in ids:
                findings = self.test_idor(self.base_url, id_info['param'], id_info['value'])
                self.findings.extend(findings)
            
        except Exception as e:
            print(f"IDOR scanning error: {e}")
        
        return self.findings
