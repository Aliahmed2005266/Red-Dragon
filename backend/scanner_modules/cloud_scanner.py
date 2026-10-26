"""
Cloud Security Scanner Module (AWS, Google Cloud, Azure)
"""

import re
import requests
from urllib.parse import urlparse

class CloudScanner:
    def __init__(self, base_url, domain, session):
        self.base_url = base_url.rstrip('/')
        self.domain = domain
        self.session = session
        self.findings = []
        
    def detect_cloud_services(self):
        """Detect cloud service usage"""
        cloud_indicators = {
            'AWS': [
                'amazonaws.com',
                'aws.amazon.com',
                's3.amazonaws.com',
                'dynamodb.amazonaws.com',
                'cloudfront.amazonaws.com',
            ],
            'Google Cloud': [
                'googleapis.com',
                'googlecloud.com',
                'storage.googleapis.com',
                'compute.googleapis.com',
                'cloud.google.com',
            ],
            'Azure': [
                'azure.com',
                'azurewebsites.net',
                'azureedge.net',
                'blob.core.windows.net',
                'database.windows.net',
            ]
        }
        
        detected_services = []
        
        try:
            response = self.session.get(self.base_url, timeout=10)
            content = response.text
            headers = str(response.headers).lower()
            
            for provider, indicators in cloud_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in content or indicator.lower() in headers:
                        detected_services.append(provider)
                        break
        except:
            pass
        
        return list(set(detected_services))

    def test_aws_metadata(self):
        """Test AWS metadata endpoint"""
        findings = []
        
        aws_metadata_urls = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/meta-data/iam/',
        ]
        
        for url in aws_metadata_urls:
            try:
                response = self.session.get(url, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    findings.append({
                        'type': 'Cloud Security',
                        'severity': 'Critical',
                        'title': 'AWS Metadata API accessible',
                        'description': 'AWS instance metadata is accessible, which could expose credentials, secrets, and configuration data.',
                        'url': url,
                        'remediation': 'Block access to AWS metadata endpoint (169.254.169.254) using firewall rules in your cloud security group.'
                    })
            except:
                continue
        
        return findings

    def test_google_cloud_metadata(self):
        """Test GCP metadata endpoint"""
        findings = []
        
        gcp_metadata_urls = [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/',
        ]
        
        headers = {'Metadata-Flavor': 'Google'}
        
        for url in gcp_metadata_urls:
            try:
                response = self.session.get(url, headers=headers, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    findings.append({
                        'type': 'Cloud Security',
                        'severity': 'Critical',
                        'title': 'GCP Metadata API accessible',
                        'description': 'GCP instance metadata is accessible, which could expose credentials and account information.',
                        'url': url,
                        'remediation': 'Hide the GCP metadata server behind firewall rules. Use firewall rules to block access from instance.'
                    })
            except:
                continue
        
        return findings

    def test_s3_bucket_exposure(self):
        """Test for S3 bucket misconfiguration"""
        findings = []
        
        try:
            response = self.session.get(self.base_url, timeout=10)
            content = response.text
            
            # Look for S3 bucket references
            s3_urls = re.findall(r'https?://[^"\']+\.s3[^"\']*\.amazonaws\.com', content)
            s3_buckets = re.findall(r'https?://s3[^"\']*\.amazonaws\.com/([^"\']+)', content)
            
            for bucket in s3_buckets:
                # Test if bucket is publicly accessible
                test_url = f"https://{bucket}.s3.amazonaws.com"
                try:
                    bucket_response = self.session.get(test_url, timeout=5)
                    if bucket_response.status_code == 200:
                        findings.append({
                            'type': 'Cloud Security',
                            'severity': 'High',
                            'title': 'S3 bucket possibly publicly accessible',
                            'description': f'S3 bucket "{bucket}" appears to be publicly accessible.',
                            'url': test_url,
                            'remediation': 'Configure bucket policies to restrict access. Enable encryption. Enable server-side logging.'
                        })
                except:
                    pass
        except:
            pass
        
        return findings

    def test_cloud_storage(self):
        """Test cloud storage configurations"""
        findings = []
        
        common_storage_paths = [
            '/s3',
            '/storage',
            '/bucket',
            '/media',
            '/uploads',
            '/static',
        ]
        
        for path in common_storage_paths:
            test_url = f"{self.base_url}{path}"
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200 and ('index of' in response.text.lower() or 
                                                     'bucket' in response.text.lower()):
                    findings.append({
                        'type': 'Cloud Security',
                        'severity': 'High',
                        'title': 'Cloud storage directory listing enabled',
                        'description': f'Cloud storage directory listing is enabled at {test_url}.',
                        'url': test_url,
                        'remediation': 'Disable directory listings for cloud storage. Use proper IAM policies.'
                    })
            except:
                continue
        
        return findings

    def scan(self):
        """Main scanning function"""
        try:
            # Detect cloud services
            cloud_services = self.detect_cloud_services()
            
            if cloud_services:
                self.findings.append({
                    'type': 'Cloud Security',
                    'severity': 'Info',
                    'title': 'Cloud services detected',
                    'description': f'Target uses: {", ".join(cloud_services)}',
                    'url': self.base_url,
                    'remediation': 'Ensure cloud security best practices are followed.'
                })
            
            # Test AWS
            if 'AWS' in cloud_services:
                findings = self.test_aws_metadata()
                self.findings.extend(findings)
                
                findings = self.test_s3_bucket_exposure()
                self.findings.extend(findings)
            
            # Test Google Cloud
            if 'Google Cloud' in cloud_services:
                findings = self.test_google_cloud_metadata()
                self.findings.extend(findings)
            
            # Test Azure
            if 'Azure' in cloud_services:
                # Similar tests for Azure
                pass
            
            # General cloud storage tests
            findings = self.test_cloud_storage()
            self.findings.extend(findings)
            
        except Exception as e:
            print(f"Cloud scanning error: {e}")
        
        return self.findings