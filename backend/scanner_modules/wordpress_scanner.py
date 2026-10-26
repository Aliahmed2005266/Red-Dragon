"""
WordPress Vulnerability Scanner Module
"""

import re
import requests
from urllib.parse import urlparse, urljoin

class WordPressScanner:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        self.wp_version = None
        
    def detect_wp_version(self):
        """Detect WordPress version"""
        version_urls = [
            '/feed',
            '/wp-json/wp/v2/',
        ]
        
        for path in version_urls:
            try:
                response = self.session.get(f"{self.base_url}{path}", timeout=5)
                
                # Check for version in generator tag
                version = re.search(r'WordPress/(\d+\.\d+\.\d+)', response.text)
                if version:
                    self.wp_version = version.group(1)
                    break
                
                # Check in JSON
                try:
                    data = response.json()
                    if 'name' in data:
                        description = data.get('description', '')
                        version = re.search(r'Version (\d+\.\d+\.\d+)', description)
                        if version:
                            self.wp_version = version.group(1)
                except:
                    pass
            except:
                continue
        
        return self.wp_version

    def test_wp_login_brute(self):
        """Test WordPress login for common issues"""
        findings = []
        
        login_urls = [
            '/wp-login.php',
            '/wp-admin/',
        ]
        
        for login_url in login_urls:
            try:
                response = self.session.get(f"{self.base_url}{login_url}", timeout=5)
                
                if response.status_code == 200:
                    findings.append({
                        'type': 'WordPress',
                        'severity': 'Info',
                        'title': 'WordPress login page accessible',
                        'description': f'WordPress login page found at {self.base_url}{login_url}',
                        'url': f"{self.base_url}{login_url}",
                        'remediation': 'Implement strong authentication. Use 2FA. Limit login attempts. Use security plugins.'
                    })
                    
                    # Check for user enumeration
                    test_url = f"{self.base_url}/?author=1"
                    author_response = self.session.get(test_url, timeout=5)
                    if author_response.status_code == 200 and '/author/' in author_response.text:
                        findings.append({
                            'type': 'WordPress',
                            'severity': 'Medium',
                            'title': 'WordPress user enumeration via author parameter',
                            'description': 'WordPress allows user enumeration through the author parameter.',
                            'url': test_url,
                            'remediation': 'Disable author archives. Remove author links. Use security plugins.'
                        })
            except:
                continue
        
        return findings

    def test_wp_plugins(self):
        """Test for vulnerable WordPress plugins"""
        findings = []
        
        common_plugins = [
            'akismet', 'jetpack', 'wordpress-seo', 'contact-form-7', 
            'duplicate-post', 'wordfence', 'woocommerce', 'elementor'
        ]
        
        for plugin in common_plugins:
            plugin_url = f"{self.base_url}/wp-content/plugins/{plugin}/readme.txt"
            try:
                response = self.session.get(plugin_url, timeout=5)
                if response.status_code == 200:
                    # Extract version
                    version = re.search(r'Stable tag: (\d+\.\d+(\.\d+)?)', response.text)
                    if version:
                        plugin_version = version.group(1)
                        findings.append({
                            'type': 'WordPress',
                            'severity': 'Medium',
                            'title': f'WordPress plugin detected: {plugin} v{plugin_version}',
                            'description': f'WordPress plugin {plugin} version {plugin_version} is installed. Verify if it has known vulnerabilities.',
                            'url': plugin_url,
                            'plugin_name': plugin,
                            'plugin_version': plugin_version,
                            'remediation': f'Keep {plugin} updated. Review plugin for vulnerabilities at wordpress.org/plugins/{plugin}/'
                        })
            except:
                continue
        
        return findings

    def test_wp_themes(self):
        """Test for WordPress theme vulnerabilities"""
        findings = []
        
        common_themes = [
            'twentytwentythree', 'twentytwentytwo', 'twentytwentyone',
            'astra', 'oceanwp', 'generatepress', 'hello-elementor'
        ]
        
        for theme in common_themes:
            theme_url = f"{self.base_url}/wp-content/themes/{theme}/style.css"
            try:
                response = self.session.get(theme_url, timeout=5)
                if response.status_code == 200:
                    # Extract version
                    version = re.search(r'Version: (\d+\.\d+(\.\d+)?)', response.text)
                    if version:
                        theme_version = version.group(1)
                        findings.append({
                            'type': 'WordPress',
                            'severity': 'Medium',
                            'title': f'WordPress theme detected: {theme} v{theme_version}',
                            'description': f'WordPress theme {theme} version {theme_version} is active. Review for known vulnerabilities.',
                            'url': theme_url,
                            'theme_name': theme,
                            'theme_version': theme_version,
                            'remediation': f'Keep theme {theme} updated. Check for vulnerabilities at wordpress.org/themes/{theme}/'
                        })
            except:
                continue
        
        return findings

    def test_wp_config(self):
        """Test for exposed WordPress configuration files"""
        findings = []
        
        config_files = [
            'wp-config.php',
            'wp-config.php.bak',
            'wp-config.php~',
            '.wp-config.php.swp',
            'readme.html',
            'license.txt',
            'xmlrpc.php',
        ]
        
        for config_file in config_files:
            file_url = f"{self.base_url}/{config_file}"
            try:
                response = self.session.get(file_url, timeout=5)
                if response.status_code == 200:
                    if config_file == 'wp-config.php':
                        findings.append({
                            'type': 'WordPress',
                            'severity': 'Critical',
                            'title': 'WordPress wp-config.php exposed',
                            'description': 'WordPress configuration file wp-config.php is accessible. This exposes database credentials and security keys.',
                            'url': file_url,
                            'remediation': 'Immediately remove wp-config.php from web-accessible directory. Move outside web root. Add to .htaccess deny rules.'
                        })
                    elif config_file in ['wp-config.php.bak', 'wp-config.php~', '.wp-config.php.swp']:
                        findings.append({
                            'type': 'WordPress',
                            'severity': 'High',
                            'title': f'WordPress config backup file found: {config_file}',
                            'description': f'WordPress configuration backup file {config_file} is publicly accessible.',
                            'url': file_url,
                            'remediation': f'Delete {config_file} immediately. Properly configure server to prevent file access.'
                        })
                    elif config_file == 'xmlrpc.php':
                        findings.append({
                            'type': 'WordPress',
                            'severity': 'Medium',
                            'title': 'XML-RPC enabled',
                            'description': 'WordPress XML-RPC is enabled, which can be abused for brute force attacks and DDoS.',
                            'url': file_url,
                            'remediation': 'Disable XML-RPC if not needed. Use security plugins to restrict access.'
                        })
                    else:
                        findings.append({
                            'type': 'WordPress',
                            'severity': 'Low',
                            'title': f'WordPress file exposed: {config_file}',
                            'description': f'WordPress file {config_file} is publicly accessible.',
                            'url': file_url,
                            'remediation': 'Move sensitive files outside web root or restrict access.'
                        })
            except:
                continue
        
        return findings

    def scan(self):
        """Main scanning function"""
        try:
            # Detect WordPress version
            self.detect_wp_version()
            
            if self.wp_version:
                self.findings.append({
                    'type': 'WordPress',
                    'severity': 'Info',
                    'title': f'WordPress version: {self.wp_version}',
                    'description': f'WordPress version {self.wp_version} detected',
                    'url': self.base_url,
                    'remediation': 'Keep WordPress updated to latest version.'
                })
            
            # Test login page
            findings = self.test_wp_login_brute()
            self.findings.extend(findings)
            
            # Test plugins
            findings = self.test_wp_plugins()
            self.findings.extend(findings)
            
            # Test themes
            findings = self.test_wp_themes()
            self.findings.extend(findings)
            
            # Test config exposure
            findings = self.test_wp_config()
            self.findings.extend(findings)
            
        except Exception as e:
            print(f"WordPress scanning error: {e}")
        
        return self.findings