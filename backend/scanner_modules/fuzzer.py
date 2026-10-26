"""
Fuzzer Module - Wordlist-based fuzzing for endpoints, parameters, and directories
"""

import requests
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner_modules.url_utils import with_param
from urllib.parse import urlparse, urljoin
import time
import re

class Fuzzer:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        self.results = []
        
        # Built-in wordlists
        self.common_dirs = [
            'admin', 'login', 'wp-admin', 'wp-content', 'uploads', 'images',
            'css', 'js', 'api', 'v1', 'v2', 'backup', 'config', 'database',
            'sql', 'admin.php', 'config.php', 'index.php', 'login.php',
            'register.php', 'api.php', 'test', 'dev', 'staging', 'beta',
            'private', 'secret', 'hidden', 'temp', 'tmp', 'logs',
            'error', 'errors', 'debug', 'info', 'status', 'health',
            'robots.txt', 'sitemap.xml', '.htaccess', '.env', 'git/config',
            'README.md', 'package.json', 'composer.json', 'web.config',
            'phpinfo.php', 'info.php', 'shell.php', 'cmd.php',
        ]
        
        self.common_files = [
            'index.php', 'index.html', 'index.asp', 'index.aspx', 'index.jsp',
            'default.php', 'default.asp', 'default.aspx', 'default.jsp',
            'home.php', 'home.html', 'home.asp',
            'admin.php', 'admin.asp', 'admin.aspx', 'admin.jsp',
            'login.php', 'login.asp', 'login.aspx', 'login.jsp',
            'config.php', 'config.asp', 'config.aspx', 'config.jsp',
            'settings.php', 'settings.asp', 'settings.aspx',
            'api.php', 'api.asp', 'api.aspx', 'api.jsp',
            'test.php', 'test.asp', 'test.aspx', 'test.jsp',
            'backup.php', 'backup.asp', 'backup.zip', 'backup.tar.gz',
            'db.php', 'db.asp', 'database.php', 'database.asp',
        ]

    def fuzz_directories(self, wordlist=None, threads=20, max_depth=2):
        """Fuzz directories with wordlist"""
        if wordlist is None:
            wordlist = self.common_dirs
        
        discovered = []
        checked = set()
        
        def check_path(path):
            if path in checked:
                return None
            checked.add(path)
            
            try:
                response = self.session.get(path, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 201, 202, 204]:
                    content_type = response.headers.get('Content-Type', '')
                    result = {
                        'url': path,
                        'status': response.status_code,
                        'size': len(response.text),
                        'type': 'directory' if path.endswith('/') else 'file',
                        'content_type': content_type
                    }
                    
                    # Classify findings
                    if response.status_code == 200:
                        if any(ext in path for ext in ['.php', '.asp', '.aspx', '.jsp']):
                            result['severity'] = 'Medium'
                            result['finding'] = f'Accessible web file: {path}'
                        elif 'admin' in path.lower() or 'login' in path.lower():
                            result['severity'] = 'High'
                            result['finding'] = f'Admin/login page accessible: {path}'
                        elif 'config' in path.lower() or 'backup' in path.lower() or 'db' in path.lower():
                            result['severity'] = 'High'
                            result['finding'] = f'Potential sensitive file: {path}'
                        elif 'api' in path.lower():
                            result['severity'] = 'Medium'
                            result['finding'] = f'API endpoint accessible: {path}'
                        else:
                            result['severity'] = 'Info'
                            result['finding'] = f'Accessible path: {path}'
                    
                    return result
                    
            except Exception as e:
                return {'url': path, 'error': str(e)}
            
            return None
        
        # Build paths to check
        paths = []
        for word in wordlist:
            paths.append(f"{self.base_url}/{word}")
            if not word.endswith(('.php', '.asp', '.aspx', '.jsp', '.html', '.zip', '.gz', '.txt', '.xml')):
                paths.append(f"{self.base_url}/{word}/")
        
        # Check paths in parallel
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_path, path): path for path in paths}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
        
        # Process findings
        for d in discovered:
            if 'finding' in d:
                self.findings.append({
                    'type': 'Fuzzing',
                    'severity': d.get('severity', 'Info'),
                    'title': d['finding'],
                    'description': f'Discovered {d["type"]} at {d["url"]} (Status: {d["status"]}, Size: {d["size"]} bytes)',
                    'url': d['url'],
                    'status_code': d.get('status'),
                    'size': d.get('size'),
                    'content_type': d.get('content_type', ''),
                    'remediation': 'Restrict access to sensitive paths. Implement proper authentication.'
                })
        
        self.results.extend(discovered)
        return discovered

    def fuzz_parameters(self, wordlist=None, param_name='id'):
        """Fuzz parameters with wordlist for injection testing"""
        if wordlist is None:
            wordlist = [1, 2, 3, 100, 'admin', 'true', 'false', 'null', 'undefined']
        
        findings = []
        for value in wordlist:
            test_url = with_param(self.base_url, param_name, value)
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code in [200, 500, 403]:
                    findings.append({
                        'type': 'Fuzzing',
                        'severity': 'Info',
                        'title': f'Parameter fuzzing result: {param_name}={value}',
                        'description': f'Parameter {param_name} with value "{value}" returned status {response.status_code}',
                        'url': test_url,
                        'param': param_name,
                        'value': str(value),
                        'status': response.status_code,
                        'remediation': 'Implement proper input validation.'
                    })
            except:
                continue
        
        self.findings.extend(findings)
        return findings

    def load_wordlist(self, wordlist_content):
        """Load custom wordlist from string content"""
        words = []
        for line in wordlist_content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('//'):
                words.append(line)
        return words

    def scan(self, wordlist=None, max_depth=2, extensions=None):
        """Main fuzzing function - uses enhanced directory enumeration"""
        dir_findings = self.enumerate_directories(
            wordlist=wordlist,
            max_depth=max_depth,
            extensions=extensions,
            recursive=True
        )
        return self.findings

    # ------------------------------------------------------------------ #
    # Fuzz-then-test chain: discover endpoints, then test them for vulns
    # ------------------------------------------------------------------ #
    STATIC_EXTENSIONS = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif',
                         '.svg', '.ico', '.woff', '.woff2', '.ttf', '.mp4')

    def _is_testable_endpoint(self, url):
        """Return True when a fuzz-discovered URL is worth vuln-testing."""
        lower = url.lower()
        if lower.endswith(self.STATIC_EXTENSIONS):
            return False
        if lower.endswith(('.txt', '.xml', '.json', '.md', '.zip', '.gz')):
            return False
        return True

    def fuzz_and_test(self, wordlist=None, vuln_tests=None,
                      max_endpoints=12, progress_callback=None):
        """Fuzz the target, then run vulnerability scanners on discovered endpoints.

        vuln_tests: iterable of test ids among
            'sqli', 'xss', 'lfi', 'redirect'  (default: all)
        Returns a summary dict with discovered endpoints and vuln findings.
        """
        tests = set(vuln_tests) if vuln_tests else {'sqli', 'xss', 'lfi', 'redirect'}

        # ---- Phase 1: fuzz directories ----
        if progress_callback:
            progress_callback("Fuzzing directories...", 5)
        discovered = self.fuzz_directories(wordlist)

        live = [d for d in discovered
                if d.get('status') in (200, 201, 202, 204) and self._is_testable_endpoint(d['url'])]
        # Prioritise higher-severity discoveries (admin/config/api first)
        severity_rank = {'High': 0, 'Medium': 1, 'Info': 2}
        live.sort(key=lambda d: severity_rank.get(d.get('severity', 'Info'), 3))
        targets = live[:max_endpoints]

        # ---- Phase 2: chained vulnerability testing ----
        summary = {
            'endpoints_discovered': len(live),
            'endpoints_tested': [],
            'vuln_findings': [],
        }

        scanner_map = {}
        if 'sqli' in tests:
            from scanner_modules.sql_injection import SQLiScanner
            scanner_map['SQL Injection'] = SQLiScanner
        if 'xss' in tests:
            from scanner_modules.xss_scanner import XSSScanner
            scanner_map['XSS'] = XSSScanner
        if 'lfi' in tests:
            from scanner_modules.lfi_scanner import LFIScanner
            scanner_map['LFI'] = LFIScanner
        if 'redirect' in tests:
            from scanner_modules.open_redirect_scanner import OpenRedirectScanner
            scanner_map['Open Redirect'] = OpenRedirectScanner

        total = max(len(targets) * len(scanner_map), 1)
        done = 0

        for endpoint in targets:
            url = endpoint['url']
            summary['endpoints_tested'].append({
                'url': url,
                'status': endpoint.get('status'),
                'size': endpoint.get('size'),
                'severity': endpoint.get('severity', 'Info'),
                'finding': endpoint.get('finding', ''),
            })

            for name, scanner_cls in scanner_map.items():
                if progress_callback:
                    progress_callback(
                        f"Testing {url} for {name}...",
                        5 + int(90 * done / total))
                done += 1
                try:
                    scanner = scanner_cls(url, self.session)
                    found = scanner.scan() or []
                    for f in found:
                        f['discovered_by'] = 'fuzzing'
                        f['fuzz_finding'] = endpoint.get('finding', '')
                    summary['vuln_findings'].extend(found)
                    self.findings.extend(found)
                except Exception as e:
                    summary['vuln_findings'].append({
                        'type': name,
                        'severity': 'Info',
                        'title': f'{name} scan error on {url}',
                        'description': str(e),
                        'url': url,
                        'discovered_by': 'fuzzing',
                    })

        if progress_callback:
            progress_callback("Completed", 100)
        return summary

    def enumerate_directories(self, wordlist=None, threads=20, max_depth=2, extensions=None, recursive=True):
        """
        Enumerate subdirectories with optional recursion and file extensions.
        """
        if wordlist is None:
            wordlist = self.common_dirs
        if extensions is None:
            extensions = ['.php', '.html', '.htm', '.bak', '.old', '.txt', '.json', '.xml']

        all_discovered = []
        checked = set()

        def check_path(path, depth=0):
            if path in checked or depth > max_depth:
                return None
            checked.add(path)
            results = []
            urls_to_check = [path]
            if not path.endswith('/'):
                for ext in extensions:
                    urls_to_check.append(f"{path}{ext}")
            for url in urls_to_check:
                if url in checked:
                    continue
                checked.add(url)
                try:
                    response = self.session.get(url, timeout=5, allow_redirects=False)
                    if response.status_code in [200, 201, 202, 204, 301, 302, 403]:
                        content_length = len(response.content)
                        if any(url.lower().endswith(ext) for ext in self.STATIC_EXTENSIONS):
                            continue
                        result = {'url': url, 'status': response.status_code, 'size': content_length, 'type': 'directory' if url.endswith('/') else 'file', 'content_type': response.headers.get('Content-Type', ''), 'depth': depth, 'severity': 'Info', 'finding': f'Accessible path: {url}'}
                        if response.status_code == 200:
                            lower_url = url.lower()
                            if any(s in lower_url for s in ['admin', 'login', 'dashboard', 'cpanel', 'wp-admin']):
                                result['severity'] = 'High'
                                result['finding'] = f'Admin/login page accessible: {url}'
                            elif any(s in lower_url for s in ['config', 'backup', 'db', 'database', '.env', '.git']):
                                result['severity'] = 'Critical'
                                result['finding'] = f'Sensitive file/directory exposed: {url}'
                            elif any(s in lower_url for s in ['api', 'swagger', 'graphql']):
                                result['severity'] = 'Medium'
                                result['finding'] = f'API endpoint accessible: {url}'
                            elif any(s in lower_url for s in ['test', 'dev', 'staging', 'debug']):
                                result['severity'] = 'Medium'
                                result['finding'] = f'Development/staging endpoint: {url}'
                            elif any(s in lower_url for s in ['upload', 'file', 'media']):
                                result['severity'] = 'Medium'
                                result['finding'] = f'Upload endpoint accessible: {url}'
                        elif response.status_code == 403:
                            result['severity'] = 'Low'
                            result['finding'] = f'Forbidden (exists but protected): {url}'
                        elif response.status_code in [301, 302]:
                            redirect_url = response.headers.get('Location', '')
                            result['finding'] = f'Redirect ({response.status_code}): {url} -> {redirect_url}'
                            result['severity'] = 'Low'
                        results.append(result)
                        if recursive and url.endswith('/') and depth < max_depth:
                            for word in wordlist[:20]:
                                sub_path = f"{url}{word}/"
                                sub_result = check_path(sub_path, depth + 1)
                                if sub_result:
                                    if isinstance(sub_result, list):
                                        results.extend(sub_result)
                                    else:
                                        results.append(sub_result)
                except Exception:
                    pass
            return results

        # Build initial paths from wordlist
        paths = []
        for word in wordlist:
            paths.append(f"{self.base_url}/{word}")
            if not word.endswith('/'):
                paths.append(f"{self.base_url}/{word}/")

        # Check paths in parallel
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_path, path, 0): path for path in paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    if isinstance(result, list):
                        all_discovered.extend(result)
                    else:
                        all_discovered.append(result)

        # Process findings
        for d in all_discovered:
            if 'finding' in d and d.get('status') == 200:
                self.findings.append({
                    'type': 'Subdirectory',
                    'severity': d.get('severity', 'Info'),
                    'title': d['finding'],
                    'description': f"Discovered {d['type']} at {d['url']} (Status: {d['status']}, Size: {d['size']} bytes, Depth: {d.get('depth', 0)})",
                    'url': d['url'],
                    'status_code': d.get('status'),
                    'size': d.get('size'),
                    'content_type': d.get('content_type', ''),
                    'depth': d.get('depth', 0),
                    'remediation': 'Restrict access to sensitive paths. Remove unnecessary files and directories. Implement proper authentication.'
                })

        self.results.extend(all_discovered)
        return all_discovered
