"""
Subdomain Enumeration Module
"""

import socket
import dns.resolver
import dns.exception
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import re

class SubdomainEnumerator:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        # Clean domain (remove port if present)
        if ':' in self.domain:
            self.domain = self.domain.split(':')[0]
        self.session = session
        self.findings = []
        self.subdomains = []
        
        # Common subdomains wordlist
        self.common_subdomains = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1',
            'ns2', 'smtp', 'secure', 'vpn', 'admin', 'cdn', 'api', 'dev',
            'staging', 'test', 'portal', 'support', 'help', 'forum', 'wiki',
            'docs', 'status', 'app', 'demo', 'm', 'mobile', 'shop', 'store',
            'checkout', 'account', 'login', 'auth', 'sso', 'static', 'media',
            'img', 'images', 'cdn', 'assets', 'files', 'uploads', 'download',
            'docs', 'kb', 'helpdesk', 'tickets', 'chat', 'livechat',
            'analytics', 'tracking', 'stats', 'monitor', 'status', 'uptime',
            'git', 'svn', 'jenkins', 'jira', 'confluence', 'wiki', 'redmine',
            'mail2', 'mail3', 'webmail2', 'email', 'outlook', 'exchange',
            'owa', 'autodiscover', 'cpanel', 'whm', 'webmail', 'cpcalendars',
            'cpcontacts', 'webdisk', 'ns', 'ns3', 'ns4', 'dns', 'dns2',
            'mx', 'pop', 'imap', 'pop3', 'imap4', 'smtp2', 'relay',
            'ftp', 'sftp', 'ssh', 'rdp', 'vnc', 'remote', 'remote2',
            'cloud', 'cloud1', 'aws', 'azure', 'gcp', 'google', 's3',
            'backup', 'backup1', 'backup2', 'db', 'mysql', 'pgsql', 'redis',
            'elastic', 'es', 'kibana', 'grafana', 'prometheus', 'influx',
            'jobs', 'careers', 'apply', 'hr', 'employees', 'staff',
            'partners', 'vendors', 'suppliers', 'affiliates',
            'news', 'press', 'media', 'events', 'calendar',
            'lms', 'learn', 'training', 'academy', 'campus',
            'web', 'website', 'site', 'new', 'old', 'beta', 'alpha',
            'stage', 'dev2', 'test2', 'prod', 'production', 'live',
            'intranet', 'extranet', 'corp', 'internal',
            'radius', 'ldap', 'directory', 'phone', 'voip',
            'report', 'reports', 'dashboard', 'board', 'metrics',
            'search', 'catalog', 'catalogue', 'directory',
            'api2', 'api3', 'v1', 'v2', 'v3', 'graphql',
            'socket', 'ws', 'wss', 'stream', 'events',
            'pay', 'payment', 'payments', 'billing', 'invoice',
            'gateway', 'checkout2', 'cart', 'wishlist',
            'newsletter', 'subscribe', 'unsubscribe',
            'affiliate', 'refer', 'referral', 'promo',
            'compliance', 'audit', 'legal', 'privacy', 'terms',
            'community', 'network', 'social', 'feed', 'feeds',
        ]

    def enumerate_dns(self, subdomains=None, threads=50):
        """Enumerate subdomains via DNS resolution"""
        if subdomains is None:
            subdomains = self.common_subdomains
        
        discovered = []
        
        def check_subdomain(sub):
            full_domain = f"{sub}.{self.domain}"
            try:
                # Try A record
                answers = dns.resolver.resolve(full_domain, 'A', lifetime=5)
                ips = [str(r) for r in answers]
                return {
                    'subdomain': full_domain,
                    'type': 'A',
                    'ips': ips,
                    'status': 'resolved'
                }
            except dns.resolver.NoAnswer:
                # Try CNAME record
                try:
                    answers = dns.resolver.resolve(full_domain, 'CNAME', lifetime=5)
                    return {
                        'subdomain': full_domain,
                        'type': 'CNAME',
                        'cname': str(answers[0]),
                        'status': 'cname'
                    }
                except:
                    return None
            except dns.resolver.NXDOMAIN:
                return None
            except dns.exception.Timeout:
                return None
            except:
                return None
        
        # Check subdomains in parallel
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
        
        return discovered

    def enumerate_http(self, subdomains=None, threads=30):
        """Enumerate subdomains via HTTP requests"""
        if subdomains is None:
            subdomains = self.common_subdomains
        
        discovered = []
        
        def check_http(sub):
            full_domain = f"{sub}.{self.domain}"
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{full_domain}"
                    response = self.session.get(url, timeout=5, allow_redirects=False)
                    
                    if response.status_code in (200, 201, 202, 204, 301, 302, 307, 308, 403):
                        return {
                            'subdomain': full_domain,
                            'url': url,
                            'status': response.status_code,
                            'title': self._extract_title(response.text),
                            'server': response.headers.get('Server', ''),
                            'content_type': response.headers.get('Content-Type', ''),
                        }
                except requests.ConnectionError:
                    continue
                except:
                    continue
            
            return None
        
        def _extract_title(html):
            match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            return match.group(1).strip() if match else ''
        
        self._extract_title = _extract_title
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_http, sub): sub for sub in subdomains}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
        
        return discovered

    def enumerate_search_engines(self):
        """Use certificate transparency logs to find subdomains"""
        discovered = []
        
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    seen = set()
                    for entry in data[:200]:
                        name = entry.get('name_value', '')
                        if name:
                            for sub in name.split('\n'):
                                sub = sub.strip()
                                if sub and sub not in seen and sub.endswith(self.domain):
                                    seen.add(sub)
                                    discovered.append({
                                        'subdomain': sub,
                                        'source': 'certificate_transparency',
                                        'status': 'discovered'
                                    })
                except:
                    pass
        except:
            pass
        
        return discovered

    def load_wordlist(self, wordlist_content):
        """Load custom subdomain wordlist"""
        words = []
        for line in wordlist_content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('//'):
                words.append(line)
        return words

    def scan(self, wordlist=None):
        """Main scanning function"""
        try:
            # Use provided wordlist or default
            subdomains = wordlist if wordlist else self.common_subdomains
            
            # DNS enumeration
            dns_results = self.enumerate_dns(subdomains)
            self.subdomains.extend(dns_results)
            
            # HTTP enumeration
            http_results = self.enumerate_http(subdomains)
            self.subdomains.extend(http_results)
            
            # Certificate transparency search
            ct_results = self.enumerate_search_engines()
            self.subdomains.extend(ct_results)
            
            # Process findings
            for sub in self.subdomains:
                domain = sub.get('subdomain', '')
                
                # Check for interesting subdomains
                interesting_keywords = ['admin', 'api', 'dev', 'staging', 'test',
                                       'backup', 'internal', 'secure', 'vpn',
                                       'jenkins', 'jira', 'git', 'db', 'mysql']
                
                severity = 'Info'
                if any(kw in domain.lower() for kw in interesting_keywords):
                    severity = 'Medium'
                if any(kw in domain.lower() for kw in ['admin', 'internal', 'backup']):
                    severity = 'High'
                
                title = sub.get('title', '')
                server = sub.get('server', '')
                ips = ', '.join(sub.get('ips', []))
                
                desc_parts = [f"Discovered subdomain: {domain}"]
                if ips:
                    desc_parts.append(f"IPs: {ips}")
                if title:
                    desc_parts.append(f"Title: {title}")
                if server:
                    desc_parts.append(f"Server: {server}")
                if sub.get('source'):
                    desc_parts.append(f"Source: {sub['source']}")
                
                self.findings.append({
                    'type': 'Subdomain Enumeration',
                    'severity': severity,
                    'title': f'Subdomain discovered: {domain}',
                    'description': '. '.join(desc_parts),
                    'url': f"https://{domain}",
                    'subdomain': domain,
                    'ips': ips,
                    'title_page': title,
                    'server': server,
                    'source': sub.get('source', 'dns'),
                    'remediation': 'Monitor subdomains, remove unused ones, secure exposed services.'
                })
            
        except Exception as e:
            print(f"Subdomain enumeration error: {e}")
        
        return self.subdomains