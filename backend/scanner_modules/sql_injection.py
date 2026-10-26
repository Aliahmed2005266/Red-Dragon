"""
SQL Injection Scanner Module
"""

import re
import requests
from scanner_modules.url_utils import with_param
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
import time

class SQLiScanner:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        
        # SQL Injection payloads
        self.sqli_payloads = [
            "'",
            "''",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'#",
            "' OR '1'='1'/*",
            "admin'--",
            "admin'#",
            "admin'/*",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' AND 1=1--",
            "' AND 1=0--",
            "' AND 1=1#",
            "' AND 1=0#",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "SLEEP(5)",
            "BENCHMARK(1000000,MD5(1))",
            "WAITFOR DELAY '0:0:5'",
            "pg_sleep(5)",
            "AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
            "AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        ]
        
        # Error-based patterns
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"ORA-[0-9]{4}",
            r"Oracle error",
            r"PostgreSQL.*ERROR",
            r"PgSQL",
            r"SQLite3::SQLException",
            r"System.Data.SQLiteException",
            r"ODBC Driver.*SQL Server",
            r"SQLServer JDBC Driver",
            r"mysql_fetch_array",
            r"syntax error",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
        ]

    def test_parameter(self, url, param_name, method='GET'):
        """Test a single parameter for SQL injection"""
        findings = []
        
        # Get base response
        try:
            if method == 'GET':
                base_response = self.session.get(url, timeout=10)
            else:
                base_response = self.session.post(url, data={}, timeout=10)
            base_status = base_response.status_code
            base_length = len(base_response.text)
        except:
            return findings
        
        # Test each payload
        for payload in self.sqli_payloads:
            try:
                if method == 'GET':
                    test_url = url.replace(f"{param_name}=", f"{param_name}={payload}")
                    response = self.session.get(test_url, timeout=10)
                else:
                    response = self.session.post(url, data={param_name: payload}, timeout=10)
                
                # Check for SQL errors
                for pattern in self.error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        findings.append({
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'title': f'SQL Injection vulnerability detected',
                            'description': f'SQL injection vulnerability found in parameter "{param_name}". Error-based SQL injection detected.',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'Pattern matched: {pattern}',
                            'remediation': 'Use parameterized queries or prepared statements. Implement proper input validation and sanitization. Use ORM frameworks with built-in SQL injection protection.'
                        })
                        return findings  # Stop testing this parameter
                
                # Boolean-based detection
                if response.status_code != base_status or abs(len(response.text) - base_length) > 100:
                    if 'true' in payload.lower() or 'false' in payload.lower() or '1=1' in payload or '1=0' in payload:
                        findings.append({
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'title': f'Possible SQL Injection (Boolean-based)',
                            'description': f'Boolean-based SQL injection vulnerability detected in parameter "{param_name}". Response behavior changes with injected boolean conditions.',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'remediation': 'Use parameterized queries or prepared statements. Implement proper input validation.'
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
                inputs = form.find_all(['input', 'textarea', 'select'])
                
                for input_field in inputs:
                    param_name = input_field.get('name')
                    if param_name:
                        # Test the parameter
                        results = self.test_parameter(form_url, param_name, method)
                        self.findings.extend(results)
            
            # Test URL parameters from the current page
            parsed = urlparse(self.base_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param_name in params.keys():
                    results = self.test_parameter(self.base_url, param_name)
                    self.findings.extend(results)
            
            # Test common parameters
            common_params = ['id', 'page', 'user', 'email', 'search', 'query', 'name', 'category']
            for param in common_params:
                test_url = with_param(self.base_url, param, "1")
                results = self.test_parameter(test_url, param)
                self.findings.extend(results)
            
        except Exception as e:
            print(f"SQLi scanning error: {e}")
        
        return self.findings
