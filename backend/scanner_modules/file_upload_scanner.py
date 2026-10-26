"""
File Upload Scanner Module
"""

import re
import requests
import os
from urllib.parse import urlparse, urljoin
import time

class FileUploadScanner:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        
        # Malicious file upload payloads
        self.malicious_files = {
            'php': {
                'content': '<?php phpinfo(); ?>',
                'filename': 'test.php',
                'content_type': 'application/x-php',
                'detection': ['PHP Version']
            },
            'asp': {
                'content': '<% Response.Write("test") %>',
                'filename': 'test.asp',
                'content_type': 'application/x-asp',
                'detection': ['ASP']
            },
            'jsp': {
                'content': '<% out.println("test"); %>',
                'filename': 'test.jsp',
                'content_type': 'application/x-jsp',
                'detection': ['JSP']
            },
            'html': {
                'content': '<html><body><script>alert("XSS")</script></body></html>',
                'filename': 'test.html',
                'content_type': 'text/html',
                'detection': []
            },
            'exe': {
                'content': b'MZ\x90\x00\x02\x00\x00\x00\x00\x00',
                'filename': 'test.exe',
                'content_type': 'application/x-msdownload',
                'detection': []
            },
            'htaccess': {
                'content': 'php_value auto_prepend_file shell.php',
                'filename': '.htaccess',
                'content_type': 'application/octet-stream',
                'detection': []
            }
        }

    def test_upload(self, url, file_field_name, method='POST'):
        """Test file upload vulnerability"""
        findings = []
        
        for file_type, file_info in self.malicious_files.items():
            try:
                files = {
                    file_field_name: (
                        file_info['filename'],
                        file_info['content'],
                        file_info['content_type']
                    )
                }
                
                if method == 'POST':
                    response = self.session.post(url, files=files, timeout=10)
                else:
                    response = self.session.post(url, files=files, timeout=10)
                
                # Check if upload succeeded
                if response.status_code in [200, 201, 302]:
                    # Try to access uploaded file
                    uploaded_filename = file_info['filename']
                    possible_urls = [
                        f"{self.base_url}/uploads/{uploaded_filename}",
                        f"{self.base_url}/images/{uploaded_filename}",
                        f"{self.base_url}/files/{uploaded_filename}",
                        f"{self.base_url}/media/{uploaded_filename}",
                    ]
                    
                    for test_url in possible_urls:
                        try:
                            file_response = self.session.get(test_url, timeout=5)
                            if file_response.status_code == 200:
                                # Check for detection patterns
                                content_lower = file_response.text.lower()
                                matches = [pattern for pattern in file_info['detection'] 
                                          if pattern.lower() in content_lower]
                                
                                if matches:
                                    findings.append({
                                        'type': 'Unrestricted File Upload',
                                        'severity': file_type == 'php' and 'Critical' or 'High',
                                        'title': f'Dangerous file type upload allowed ({file_type.upper()})',
                                        'description': f'Server allows uploading {file_type.upper()} files which can lead to Remote Code Execution (RCE).',
                                        'url': url,
                                        'uploaded_file': uploaded_filename,
                                        'accessible_at': test_url,
                                        'file_type': file_type,
                                        'remediation': 'Implement strict file type validation. Only allow necessary file types. Store uploads outside web root. Use random filenames. Implement file content validation.'
                                    })
                                    break
                        except:
                            continue
                            
            except Exception as e:
                continue
        
        return findings

    def scan(self):
        """Main scanning function"""
        try:
            response = self.session.get(self.base_url, timeout=10)
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms with file inputs
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
                
                # Find file inputs
                file_inputs = form.find_all('input', {'type': 'file'})
                
                for file_input in file_inputs:
                    field_name = file_input.get('name', 'file')
                    results = self.test_upload(form_url, field_name, method)
                    self.findings.extend(results)
                
                # Also test with both field name possibilities
                if not file_inputs:
                    results = self.test_upload(form_url, 'file', method)
                    self.findings.extend(results)
                    results = self.test_upload(form_url, 'upload', method)
                    self.findings.extend(results)
            
            # Check for common upload endpoints
            upload_paths = [
                '/upload',
                '/upload.php',
                '/uploadfile',
                '/fileupload',
                '/api/upload',
                '/api/v1/upload'
            ]
            
            for path in upload_paths:
                test_url = urljoin(self.base_url, path)
                results = self.test_upload(test_url, 'file')
                self.findings.extend(results)
                
        except Exception as e:
            print(f"File upload scanning error: {e}")
        
        return self.findings