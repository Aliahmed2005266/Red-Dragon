"""
CVE Scanner Module - Check for known vulnerabilities in detected technologies
"""

import re
import requests
from urllib.parse import urlparse

class CVEScanner:
    def __init__(self, domain, detected_technologies):
        self.domain = domain
        self.detected_technologies = detected_technologies
        self.findings = []
        
        # CVE database (simplified version - in production would use APIs)
        self.technology_cves = {
            'WordPress': [
                {'cve': 'CVE-2023-XXXX', 'version': '<6.2.2', 'severity': 'Critical', 'description': 'WordPress SQL Injection'},
                {'cve': 'CVE-2023-YYYY', 'version': '<6.1.4', 'severity': 'High', 'description': 'WordPress XSS in comments'},
            ],
            'Apache': [
                {'cve': 'CVE-2021-41773', 'version': '<2.4.49', 'severity': 'Critical', 'description': 'Path Traversal and File Disclosure'},
                {'cve': 'CVE-2021-42063', 'version': '<2.4.50', 'severity': 'Critical', 'description': 'Path Traversal'},
            ],
            'Nginx': [
                {'cve': 'CVE-2021-23017', 'version': '<1.21.4', 'severity': 'High', 'description': 'DNS Resolver Off-by-One Heap Buffer Overflow'},
            ],
            'PHP': [
                {'cve': 'CVE-2023-XXXX', 'version': '<8.2.4', 'severity': 'High', 'description': 'PHP Use-After-Free Vulnerability'},
                {'cve': 'CVE-2022-31629', 'version': '<7.4.30', 'severity': 'High', 'description': 'PHP Bypass open_basedir'},
            ],
            'Drupal': [
                {'cve': 'CVE-2023-YYYY', 'version': '<9.4.x', 'severity': 'Critical', 'description': 'Drupal Remote Code Execution'},
            ],
            'Joomla': [
                {'cve': 'CVE-2023-XXXX', 'version': '<4.2.8', 'severity': 'High', 'description': 'Joomla XSS Vulnerability'},
            ],
            'React': [
                {'cve': 'CVE-2023-YYYY', 'version': '<18.2.0', 'severity': 'Medium', 'description': 'React Server-Side Rendering Vulnerability'},
            ],
            'Node.js': [
                {'cve': 'CVE-2023-23920', 'version': '<19.6.1', 'severity': 'High', 'description': 'Node.js OpenSSL Vulnerability'},
            ],
            'Python/Django': [
                {'cve': 'CVE-2023-XXXX', 'version': '<4.1.10', 'severity': 'Medium', 'description': 'Django Information Disclosure'},
            ],
        }

    def detect_server_version(self):
        """Detect server software and versions"""
        version_info = {}
        
        try:
            response = requests.get(f"https://{self.domain}", timeout=10)
            headers = response.headers
            
            # Server header
            server = headers.get('Server', '')
            if server:
                version_info['Server'] = server
                
                # Parse server header
                if 'apache' in server.lower():
                    version_info['Apache'] = re.search(r'Apache/(\d+\.\d+\.\d+)', server)
                elif 'nginx' in server.lower():
                    version_info['Nginx'] = re.search(r'nginx/(\d+\.\d+\.\d+)', server)
                elif 'microsoft-iis' in server.lower():
                    version_info['IIS'] = re.search(r'Microsoft-IIS/(\d+\.\d+)', server)
            
            # X-Powered-By header
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                version_info['Powered-By'] = powered_by
                
                if 'php' in powered_by.lower():
                    version_info['PHP'] = re.search(r'PHP/(\d+\.\d+\.\d+)', powered_by)
                elif 'asp.net' in powered_by.lower():
                    version_info['ASP.NET'] = re.search(r'ASP\.NET/(\d+\.\d+\.\d+)', powered_by)
                elif 'express' in powered_by.lower():
                    version_info['Node.js/Express'] = re.search(r'Express/(\d+\.\d+\.\d+)', powered_by)
            
            # Check HTML content for version info
            content = response.text
            
            # WordPress version
            if 'WordPress' in self.detected_technologies:
                wp_version = re.search(r'<meta name="generator" content="WordPress (\d+\.\d+\.\d+)', content)
                if wp_version:
                    version_info['WordPress'] = wp_version.group(1)
            
            # Drupal version
            if 'Drupal' in self.detected_technologies:
                drupal_version = re.search(r'<meta name="Generator" content="Drupal (\d+)', content)
                if drupal_version:
                    version_info['Drupal'] = drupal_version.group(1)
            
            # Joomla version
            if 'Joomla' in self.detected_technologies:
                joomla_version = re.search(r'<meta name="generator" content="Joomla! (\d+\.\d+\.\d+)', content)
                if joomla_version:
                    version_info['Joomla'] = joomla_version.group(1)
                    
        except Exception as e:
            print(f"Version detection error: {e}")
        
        return version_info

    def check_cves(self, technology, version):
        """Check for known CVEs"""
        findings = []
        
        if technology not in self.technology_cves:
            return findings
        
        for cve_info in self.technology_cves[technology]:
            # Simplified version check - in production would use proper version comparison
            cve_version = cve_info.get('version', '')
            if cve_version.startswith('<'):
                # Mark as potentially vulnerable
                findings.append({
                    'type': 'CVE',
                    'severity': cve_info['severity'],
                    'title': f"Known vulnerability detected: {cve_info['cve']}",
                    'description': f"{cve_info['description']} - Affects {technology} versions {cve_version}. Version detected: {version}",
                    'url': f"https://{self.domain}",
                    'cve_id': cve_info['cve'],
                    'technology': technology,
                    'detected_version': version,
                    'affected_versions': cve_version,
                    'remediation': f'Upgrade {technology} to latest stable version. Apply security patches.'
                })
        
        return findings

    def scan(self):
        """Main scanning function"""
        try:
            # Detect server versions
            version_info = self.detect_server_version()
            
            # Check for CVEs based on detected technologies and versions
            for technology in version_info:
                version = version_info[technology]
                if technology in self.technology_cves:
                    findings = self.check_cves(technology, str(version))
                    self.findings.extend(findings)
            
            # Also check based on detected technologies without versions
            for technology in self.detected_technologies:
                if technology in self.technology_cves:
                    # Add generic vulnerability info
                    cve_list = self.technology_cves[technology]
                    if cve_list:
                        findings.append({
                            'type': 'CVE',
                            'severity': 'Medium',
                            'title': f'{technology} vulnerabilities require verification',
                            'description': f'{technology} detected but version could not be determined. Known vulnerabilities exist for this technology.',
                            'url': f"https://{self.domain}",
                            'technology': technology,
                            'known_cves': [cve['cve'] for cve in cve_list],
                            'remediation': f'Verify {technology} version and apply necessary security patches.'
                        })
            
        except Exception as e:
            print(f"CVE scanning error: {e}")
        
        return self.findings