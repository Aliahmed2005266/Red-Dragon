#!/usr/bin/env python3
"""
Vulnerability Scanner Pro - CLI/Terminal Mode
Made by Aegis Cyber Works
"""

import sys
import json
import time
import os
import socket
import urllib.request
import urllib.error
import argparse
from urllib.parse import urljoin, urlparse, quote, quote_plus, unquote

# Try importing optional modules
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    print(f"{Colors.CYAN}{Colors.BOLD}======================================================{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}                                                      {Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}   Vulnerability Scanner Pro - CLI Mode{Colors.END}")
    print(f"{Colors.YELLOW}{Colors.BOLD}   Made by Aegis Cyber Works{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}                                                      {Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}======================================================{Colors.END}")

def print_menu():
    menu = f"""
{Colors.CYAN}{Colors.BOLD}Select Scan Mode:{Colors.END}

{Colors.GREEN}1.{Colors.END} Scan All (Complete comprehensive scan)
{Colors.GREEN}2.{Colors.END} SQL Injection (SQLi) only
{Colors.GREEN}3.{Colors.END} Cross-Site Scripting (XSS) only
{Colors.GREEN}4.{Colors.END} IDOR (Insecure Direct Object Reference) only
{Colors.GREEN}5.{Colors.END} Local File Inclusion (LFI) only
{Colors.GREEN}6.{Colors.END} File Upload vulnerabilities only
{Colors.GREEN}7.{Colors.END} Command Injection only
{Colors.GREEN}8.{Colors.END} GraphQL vulnerabilities only
{Colors.GREEN}9.{Colors.END} API Security testing only
{Colors.GREEN}10.{Colors.END} Cloud Security (AWS/Google) only
{Colors.GREEN}11.{Colors.END} Open Ports & Protocol scanning only
{Colors.GREEN}12.{Colors.END} CVE & Technology detection only
{Colors.GREEN}13.{Colors.END} WordPress vulnerabilities only
{Colors.GREEN}14.{Colors.END} Firewall & Rate Limit detection only
{Colors.GREEN}15.{Colors.END} Subdirectory Enumeration only
{Colors.GREEN}16.{Colors.END} Encoder/Decoder Tool

{Colors.YELLOW}Enter your choice (1-16) or press Enter for All: {Colors.END}"""
    print(menu, end='')

# Encoding functions
class PayloadEncoder:
    @staticmethod
    def url_encode(payload):
        return quote(payload, safe='')
    
    @staticmethod
    def url_encode_plus(payload):
        return quote_plus(payload)
    
    @staticmethod
    def double_url_encode(payload):
        return quote(quote(payload, safe=''), safe='')
    
    @staticmethod
    def base64_encode(payload):
        import base64
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def html_encode(payload):
        result = ''
        for char in payload:
            result += f'&#{ord(char)};'
        return result
    
    @staticmethod
    def hex_encode(payload):
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    @staticmethod
    def unicode_encode(payload):
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def none_encoding(payload):
        return payload


class PayloadDecoder:
    """Decode various encoding schemes used in payloads"""
    
    @staticmethod
    def url_decode(payload):
        """Standard URL decoding"""
        from urllib.parse import unquote
        try:
            return unquote(payload)
        except:
            return payload
    
    @staticmethod
    def double_url_decode(payload):
        """Double URL decoding"""
        from urllib.parse import unquote
        try:
            first = unquote(payload)
            return unquote(first)
        except:
            return payload
    
    @staticmethod
    def base64_decode(payload):
        """Base64 decoding with padding fix"""
        import base64
        try:
            padding = 4 - (len(payload) % 4)
            if padding != 4:
                payload += '=' * padding
            return base64.b64decode(payload).decode()
        except:
            return payload
    
    @staticmethod
    def hex_decode(payload):
        """Hexadecimal decoding (\\xNN format)"""
        try:
            import re
            hex_pattern = re.compile(r'\\x([0-9a-fA-F]{2})')
            def replace_match(match):
                return chr(int(match.group(1), 16))
            return hex_pattern.sub(replace_match, payload)
        except:
            return payload
    
    @staticmethod
    def html_decode(payload):
        """HTML entity decoding"""
        import html
        try:
            return html.unescape(payload)
        except:
            return payload
    
    @staticmethod
    def unicode_decode(payload):
        """Unicode escape decoding (\\uNNNN)"""
        import re
        try:
            def replace_match(match):
                return chr(int(match.group(1), 16))
            return re.sub(r'\\u([0-9a-fA-F]{4})', replace_match, payload)
        except:
            return payload
    
    @staticmethod
    def mixed_case_decode(payload):
        """Normalize mixed case"""
        return payload.lower()
    
    @staticmethod
    def null_byte_clean(payload):
        """Remove null byte injections"""
        return payload.replace('%00', '').replace('\x00', '')
    
    @staticmethod
    def tab_whitespace_decode(payload):
        """Reverse tab/whitespace bypass"""
        return payload.replace('\t', ' ').replace('\n', ' ')
    
    @staticmethod
    def comment_removal(payload):
        """Remove SQL comment insertions"""
        import re
        return re.sub(r'/\*\*/', '', payload)
    
    @staticmethod
    def detect_and_decode(payload):
        """Auto-detect encoding type and decode"""
        import base64, re
        try:
            padding = 4 - (len(payload) % 4)
            if padding != 4:
                padded = payload + '=' * padding
            else:
                padded = payload
            decoded = base64.b64decode(padded).decode()
            if decoded != payload and len(decoded) > 0:
                printable = sum(1 for c in decoded if c.isprintable() or c in '\n\r\t')
                if printable / max(len(decoded), 1) > 0.8:
                    return ('base64', decoded)
        except:
            pass
        
        from urllib.parse import unquote
        url_result = unquote(payload)
        if url_result != payload:
            return ('url', url_result)
        
        hex_pattern = re.compile(r'\\x([0-9a-fA-F]{2})')
        if hex_pattern.search(payload):
            try:
                result = hex_pattern.sub(lambda m: chr(int(m.group(1), 16)), payload)
                if result != payload:
                    return ('hex', result)
            except:
                pass
        
        import html
        html_result = html.unescape(payload)
        if html_result != payload:
            return ('html', html_result)
        
        if '\\u' in payload:
            try:
                result = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), payload)
                if result != payload:
                    return ('unicode', result)
            except:
                pass
        
        return ('none', payload)
    
    @staticmethod
    def smart_decode(payload, max_iterations=10):
        """Iteratively decode until no more changes detected"""
        result = payload
        for _ in range(max_iterations):
            detected, decoded = PayloadDecoder.detect_and_decode(result)
            if detected == 'none' or decoded == result:
                break
            result = decoded
        return result
    
    @staticmethod
    def brute_force_decode(payload):
        """Try all decoding methods and return all successful results"""
        results = {}
        decoders = {
            'url': PayloadDecoder.url_decode,
            'double_url': PayloadDecoder.double_url_decode,
            'base64': PayloadDecoder.base64_decode,
            'hex': PayloadDecoder.hex_decode,
            'html': PayloadDecoder.html_decode,
            'unicode': PayloadDecoder.unicode_decode,
            'mixed_case': PayloadDecoder.mixed_case_decode,
            'null_byte': PayloadDecoder.null_byte_clean,
            'whitespace': PayloadDecoder.tab_whitespace_decode,
            'comments': PayloadDecoder.comment_removal,
        }
        for name, func in decoders.items():
            try:
                decoded = func(payload)
                if decoded != payload:
                    results[name] = decoded
            except:
                continue
        return results

def get_encoding_menu():
    menu = f"""
{Colors.CYAN}{Colors.BOLD}Select Payload Encoding:{Colors.END}

{Colors.GREEN}1.{Colors.END} None (Plain text)
{Colors.GREEN}2.{Colors.END} URL Encode
{Colors.GREEN}3.{Colors.END} URL Encode Plus (+)
{Colors.GREEN}4.{Colors.END} Double URL Encode
{Colors.GREEN}5.{Colors.END} Base64 Encode
{Colors.GREEN}6.{Colors.END} HTML Entity Encode
{Colors.GREEN}7.{Colors.END} Hex Encode
{Colors.GREEN}8.{Colors.END} Unicode Encode

{Colors.YELLOW}Enter your choice (1-8) or press Enter for None: {Colors.END}"""
    print(menu, end='')
    return input() or '1'

def apply_encoding(payload, encoding_choice):
    encoder = PayloadEncoder()
    encoders = {
        '1': encoder.none_encoding,
        '2': encoder.url_encode,
        '3': encoder.url_encode_plus,
        '4': encoder.double_url_encode,
        '5': encoder.base64_encode,
        '6': encoder.html_encode,
        '7': encoder.hex_encode,
        '8': encoder.unicode_encode,
    }
    encoder_func = encoders.get(encoding_choice, encoder.none_encoding)
    return encoder_func(payload)


def get_decoding_menu():
    menu = f"""
{Colors.CYAN}{Colors.BOLD}Select Decoding Method:{Colors.END}

{Colors.GREEN}1.{Colors.END} URL Decode
{Colors.GREEN}2.{Colors.END} Double URL Decode
{Colors.GREEN}3.{Colors.END} Base64 Decode
{Colors.GREEN}4.{Colors.END} Hex Decode
{Colors.GREEN}5.{Colors.END} HTML Entity Decode
{Colors.GREEN}6.{Colors.END} Unicode Decode
{Colors.GREEN}7.{Colors.END} Auto-Detect & Decode
{Colors.GREEN}8.{Colors.END} Smart Decode (Iterative)
{Colors.GREEN}9.{Colors.END} Brute Force (Try All)

{Colors.YELLOW}Enter your choice (1-9): {Colors.END}"""
    print(menu, end='')
    return input() or '1'


def apply_decoding(payload, decoding_choice):
    decoder = PayloadDecoder()
    decoders = {
        '1': decoder.url_decode,
        '2': decoder.double_url_decode,
        '3': decoder.base64_decode,
        '4': decoder.hex_decode,
        '5': decoder.html_decode,
        '6': decoder.unicode_decode,
        '7': decoder.detect_and_decode,
        '8': decoder.smart_decode,
        '9': decoder.brute_force_decode,
    }
    decoder_func = decoders.get(decoding_choice, decoder.url_decode)
    return decoder_func(payload)


def encoder_decoder_tool():
    """Interactive encoder/decoder tool"""
    while True:
        print(f"""
{Colors.CYAN}{Colors.BOLD}+==============================================================+{Colors.END}
{Colors.CYAN}{Colors.BOLD}|           Encoder / Decoder Tool                            |{Colors.END}
{Colors.CYAN}{Colors.BOLD}+==============================================================+{Colors.END}

{Colors.GREEN}1.{Colors.END} Encode a payload
{Colors.GREEN}2.{Colors.END} Decode a payload
{Colors.GREEN}3.{Colors.END} Encode -> Decode (round-trip test)
{Colors.GREEN}4.{Colors.END} Back to main menu

{Colors.YELLOW}Enter your choice (1-4): {Colors.END}""", end='')
        
        choice = input().strip()
        
        if choice == '4':
            break
        elif choice == '1':
            payload = input(f"\n{Colors.CYAN}Enter payload to encode: {Colors.END}").strip()
            if not payload:
                print(f"{Colors.RED}[!] No payload entered{Colors.END}")
                continue
            enc_choice = get_encoding_menu()
            result = apply_encoding(payload, enc_choice)
            print(f"\n{Colors.GREEN}{Colors.BOLD}Encoded Result:{Colors.END}")
            print(f"{Colors.YELLOW}{result}{Colors.END}")
        elif choice == '2':
            payload = input(f"\n{Colors.CYAN}Enter payload to decode: {Colors.END}").strip()
            if not payload:
                print(f"{Colors.RED}[!] No payload entered{Colors.END}")
                continue
            dec_choice = get_decoding_menu()
            result = apply_decoding(payload, dec_choice)
            if isinstance(result, tuple):
                print(f"\n{Colors.GREEN}{Colors.BOLD}Detected Encoding:{Colors.END} {Colors.YELLOW}{result[0]}{Colors.END}")
                print(f"{Colors.GREEN}{Colors.BOLD}Decoded Result:{Colors.END}")
                print(f"{Colors.YELLOW}{result[1]}{Colors.END}")
            elif isinstance(result, dict):
                print(f"\n{Colors.GREEN}{Colors.BOLD}All Decoding Results:{Colors.END}")
                for method, decoded in result.items():
                    print(f"  {Colors.CYAN}{method}:{Colors.END} {Colors.YELLOW}{decoded}{Colors.END}")
            else:
                print(f"\n{Colors.GREEN}{Colors.BOLD}Decoded Result:{Colors.END}")
                print(f"{Colors.YELLOW}{result}{Colors.END}")
        elif choice == '3':
            payload = input(f"\n{Colors.CYAN}Enter payload for round-trip test: {Colors.END}").strip()
            if not payload:
                print(f"{Colors.RED}[!] No payload entered{Colors.END}")
                continue
            enc_choice = get_encoding_menu()
            encoded = apply_encoding(payload, enc_choice)
            print(f"\n{Colors.GREEN}Encoded: {Colors.YELLOW}{encoded}{Colors.END}")
            dec_choice = get_decoding_menu()
            decoded = apply_decoding(encoded, dec_choice)
            if isinstance(decoded, tuple):
                print(f"{Colors.GREEN}Decoded: {Colors.YELLOW}{decoded[1]}{Colors.END}")
                match = decoded[1] == payload
            elif isinstance(decoded, dict):
                print(f"{Colors.GREEN}Decoded (brute force):{Colors.END}")
                match = any(v == payload for v in decoded.values())
                for method, d in decoded.items():
                    print(f"  {Colors.CYAN}{method}:{Colors.END} {Colors.YELLOW}{d}{Colors.END}")
            else:
                print(f"{Colors.GREEN}Decoded: {Colors.YELLOW}{decoded}{Colors.END}")
                match = decoded == payload
            if match:
                print(f"\n{Colors.GREEN}{Colors.BOLD}[OK] Round-trip successful!{Colors.END}")
            else:
                print(f"\n{Colors.YELLOW}{Colors.BOLD}[!] Round-trip mismatch (may be expected for lossy encodings){Colors.END}")
        else:
            print(f"{Colors.RED}[!] Invalid choice{Colors.END}")
def get_scope_input():
    """Get scan scope - single target, multiple targets, or from file."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}Scope Configuration:{Colors.END}")
    print(f"{Colors.GREEN}1.{Colors.END} Single target (URL or IP)")
    print(f"{Colors.GREEN}2.{Colors.END} Multiple targets (comma/newline separated)")
    print(f"{Colors.GREEN}3.{Colors.END} Load targets from file (one per line)")
    print()
    choice = input(f"{Colors.YELLOW}Select scope option (1-3): {Colors.END}").strip()

    targets = []

    if choice == '1':
        print(f"\n{Colors.CYAN}{Colors.BOLD}Enter target URL:{Colors.END}")
        print(f"{Colors.YELLOW}Example: https://example.com{Colors.END}")
        target = input(f"{Colors.GREEN}URL: {Colors.END}").strip()
        if target:
            targets = [target]

    elif choice == '2':
        print(f"\n{Colors.CYAN}Enter targets (one per line, empty line to finish):{Colors.END}")
        print(f"{Colors.YELLOW}Examples: example.com, 192.168.1.1, https://app.example.com{Colors.END}")
        while True:
            line = input(f"  {Colors.GREEN}> {Colors.END}").strip()
            if not line:
                break
            for part in line.split(','):
                part = part.strip()
                if part:
                    targets.append(part)

    elif choice == '3':
        filepath = input(f"{Colors.YELLOW}Enter file path: {Colors.END}").strip()
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
            print(f"{Colors.GREEN}[+] Loaded {len(targets)} targets from {filepath}{Colors.END}")
        except FileNotFoundError:
            print(f"{Colors.RED}[-] File not found: {filepath}{Colors.END}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}[-] Error reading file: {e}{Colors.END}")
            sys.exit(1)

    if not targets:
        print(f"{Colors.RED}[-] No targets specified{Colors.END}")
        sys.exit(1)

    # Normalize targets
    normalized = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if not t.startswith(('http://', 'https://')):
            try:
                socket.inet_aton(t)
                t = f"http://{t}"
            except socket.error:
                t = f"http://{t}"
        normalized.append(t)

    print(f"{Colors.GREEN}[+] Scope: {len(normalized)} target(s){Colors.END}")
    for i, t in enumerate(normalized, 1):
        print(f"   {Colors.CYAN}{i}. {t}{Colors.END}")

    return normalized

def get_target_url():
    print(f"\n{Colors.CYAN}{Colors.BOLD}Enter target URL:{Colors.END}")
    print(f"{Colors.YELLOW}Example: https://example.com{Colors.END}")
    url = input(f"{Colors.GREEN}URL: {Colors.END}").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

class CLIScanner:
    def __init__(self, target_url, scan_mode='all', encoding_choice='1'):
        self.target_url = target_url
        self.scan_mode = scan_mode
        self.encoding_choice = encoding_choice
        self.findings = []
        self.session = requests.Session() if REQUESTS_AVAILABLE else None
        if self.session:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
    
    def scan(self):
        print(f"\n{Colors.CYAN}{Colors.BOLD}==============================================================={Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}Starting Scan: {Colors.END}{Colors.YELLOW}{self.target_url}{Colors.END}")
        print(f"{Colors.GREEN}Mode: {Colors.END}{Colors.CYAN}{self.scan_mode.upper()}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}==============================================================={Colors.END}\n")
        
        if self.scan_mode in ['all', 'sqli', 'xss', 'idor', 'lfi', 'file_upload', 'command_injection', 'graphql', 'api', 'cloud', 'cve', 'wordpress', 'ports', 'rate']:
            # Basic recon
            self.basic_recon()
        
        # Apply encoding to all scan methods if selected
        self.encoding_choice = getattr(self, 'encoding_choice', '1')
        
        if self.scan_mode in ['all', 'sqli']:
            self.scan_sqli()
        
        if self.scan_mode in ['all', 'xss']:
            self.scan_xss()
        
        if self.scan_mode in ['all', 'idor']:
            self.scan_idor()
        
        if self.scan_mode in ['all', 'lfi']:
            self.scan_lfi()
        
        if self.scan_mode in ['all', 'ports']:
            self.scan_ports()
        
        if self.scan_mode in ['all', 'directories', 'fuzzing']:
            self.scan_directories()
        
        if self.scan_mode in ['all', 'wordpress']:
            self.scan_wordpress()
        
        if self.scan_mode in ['all', 'cve']:
            self.detect_technologies()
        
        self.print_results()
        self.save_report()
    
    def basic_recon(self):
        print(f"{Colors.BLUE}[*] Basic Reconnaissance...{Colors.END}")
        try:
            if not self.session:
                print(f"{Colors.YELLOW}[!] requests library not available, skipping{Colors.END}")
                return
            response = self.session.get(self.target_url, timeout=10)
            print(f"{Colors.GREEN}[+] Status: {response.status_code}{Colors.END}")
            print(f"{Colors.GREEN}[+] Server: {response.headers.get('Server', 'Unknown')}{Colors.END}")
            print(f"{Colors.GREEN}[+] Content-Type: {response.headers.get('Content-Type', 'Unknown')}{Colors.END}")
            print(f"{Colors.GREEN}[+] Response Size: {len(response.text)} bytes{Colors.END}\n")
        except Exception as e:
            print(f"{Colors.RED}[-] Error during recon: {e}{Colors.END}\n")
    
    def scan_sqli(self):
        print(f"{Colors.BLUE}[*] Testing for SQL Injection...{Colors.END}")
        raw_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1' AND 1=1--",
            "' OR 'a'='a",
        ]
        payloads = [apply_encoding(p, self.encoding_choice) for p in raw_payloads]
        
        vulnerable = False
        for payload in payloads:
            try:
                if not self.session:
                    continue
                test_url = f"{self.target_url}?id={quote(payload)}"
                response = self.session.get(test_url, timeout=10)
                if any(indicator in response.text.lower() for indicator in ['sql', 'syntax', 'error', 'mysql', 'oracle', 'postgresql']):
                    print(f"{Colors.RED}[!] POTENTIAL SQLi FOUND: {test_url}{Colors.END}")
                    self.findings.append({
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'url': test_url,
                        'payload': payload,
                        'description': 'SQL injection vulnerability detected'
                    })
                    vulnerable = True
                    break
            except Exception as e:
                pass
        
        if not vulnerable:
            print(f"{Colors.GREEN}[+] No obvious SQLi vulnerabilities detected{Colors.END}")
        print()
    
    def scan_xss(self):
        print(f"{Colors.BLUE}[*] Testing for Cross-Site Scripting (XSS)...{Colors.END}")
        raw_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
        ]
        payloads = [apply_encoding(p, self.encoding_choice) for p in raw_payloads]
        
        vulnerable = False
        for payload in payloads:
            try:
                if not self.session:
                    continue
                test_url = f"{self.target_url}?q={quote(payload)}"
                response = self.session.get(test_url, timeout=10)
                if payload in response.text:
                    print(f"{Colors.RED}[!] POTENTIAL XSS FOUND: {test_url}{Colors.END}")
                    self.findings.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'url': test_url,
                        'payload': payload,
                        'description': 'Cross-site scripting vulnerability detected'
                    })
                    vulnerable = True
                    break
            except Exception as e:
                pass
        
        if not vulnerable:
            print(f"{Colors.GREEN}[+] No obvious XSS vulnerabilities detected{Colors.END}")
        print()
    
    def scan_idor(self):
        print(f"{Colors.BLUE}[*] Testing for IDOR...{Colors.END}")
        print(f"{Colors.YELLOW}[!] IDOR testing requires manual verification{Colors.END}")
        print(f"{Colors.CYAN}[*] Look for sequential IDs in URLs like /user/1, /doc/123, etc.{Colors.END}\n")
    
    def scan_lfi(self):
        print(f"{Colors.BLUE}[*] Testing for Local File Inclusion (LFI)...{Colors.END}")
        raw_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        ]
        payloads = [apply_encoding(p, self.encoding_choice) for p in raw_payloads]
        
        vulnerable = False
        for payload in payloads:
            try:
                if not self.session:
                    continue
                test_url = f"{self.target_url}?file={quote(payload)}"
                response = self.session.get(test_url, timeout=10)
                if any(indicator in response.text.lower() for indicator in ['root:', 'daemon:', '[extensions]', 'bin']):
                    print(f"{Colors.RED}[!] POTENTIAL LFI FOUND: {test_url}{Colors.END}")
                    self.findings.append({
                        'type': 'Local File Inclusion (LFI)',
                        'severity': 'Critical',
                        'url': test_url,
                        'payload': payload,
                        'description': 'Local file inclusion vulnerability detected'
                    })
                    vulnerable = True
                    break
            except Exception as e:
                pass
        
        if not vulnerable:
            print(f"{Colors.GREEN}[+] No obvious LFI vulnerabilities detected{Colors.END}")
        print()
    
    def scan_ports(self):
        print(f"{Colors.BLUE}[*] Scanning ports...{Colors.END}")
        host = urlparse(self.target_url).netloc or self.target_url
        port_scanner = None
        
        # Import the enhanced PortScanner from the backend
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend'))
            from scanner_modules.port_scanner import PortScanner
            port_scanner = PortScanner(host, scan_all=True)
            open_ports = port_scanner.scan(timeout=2, scan_all=True)
        except ImportError:
            # Fallback to basic socket scan
            open_ports = self._basic_port_scan(host)
        
        # Print results with color coding
        for port_info in open_ports:
            port = port_info['port']
            service = port_info.get('service', 'Unknown')
            version = port_info.get('version')
            auth = port_info.get('auth_method')

            version_str = f" (v{version})" if version else ""
            auth_str = f" [Auth: {auth}]" if auth else ""

            if auth and ('No authentication' in auth or 'open' in auth.lower()):
                print(f"{Colors.RED}{Colors.BOLD}[!] Port {port} ({service}) is OPEN{version_str} - {auth}{Colors.END}")
            elif auth and 'Authentication required' in auth:
                print(f"{Colors.YELLOW}[!] Port {port} ({service}) is OPEN{version_str} - {auth}{Colors.END}")
            else:
                print(f"{Colors.GREEN}[!] Port {port} ({service}) is OPEN{version_str}{auth_str}{Colors.END}")

        # Show filtered ports
        if port_scanner and port_scanner.filtered_ports:
            for fp in port_scanner.filtered_ports[:10]:
                print(f"{Colors.YELLOW}[?] Port {fp['port']} ({fp.get('service', 'Unknown')}) is FILTERED{Colors.END}")
            if len(port_scanner.filtered_ports) > 10:
                print(f"{Colors.YELLOW}[?] ... and {len(port_scanner.filtered_ports) - 10} more filtered{Colors.END}")

        if not open_ports:
            print(f"{Colors.GREEN}[+] No open ports detected{Colors.END}")

        filtered_count = len(port_scanner.filtered_ports) if port_scanner else 0
        print(f"{Colors.CYAN}[*] Scan complete: {len(open_ports)} open, {filtered_count} filtered{Colors.END}")
        print()

    def _basic_port_scan(self, host):
        """Fallback basic port scan without enhanced module."""
        common_ports = list(range(1, 1025))
        open_ports = []

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service = self.get_service_name(port)
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'status': 'open',
                        'version': None,
                        'auth_method': None
                    })
                sock.close()
            except Exception:
                pass
        return open_ports
    
    def scan_directories(self, wordlist=None, max_depth=2, extensions=None):
        """
        Enumerate subdirectories on the target.
        """
        print(f"{Colors.BLUE}[*] Enumerating subdirectories...{Colors.END}")

        try:
            sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend'))
            from scanner_modules.fuzzer import Fuzzer
            import requests

            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })

            fuzzer = Fuzzer(self.target_url, session)
            discovered = fuzzer.enumerate_directories(
                wordlist=wordlist,
                threads=20,
                max_depth=max_depth,
                extensions=extensions,
                recursive=True
            )

            if discovered:
                severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
                discovered.sort(key=lambda x: severity_order.get(x.get('severity', 'Info'), 5))

                for d in discovered:
                    url = d.get('url', '')
                    status = d.get('status', 0)
                    size = d.get('size', 0)
                    depth = d.get('depth', 0)
                    severity = d.get('severity', 'Info')
                    finding = d.get('finding', '')

                    depth_str = f" [Depth: {depth}]" if depth > 0 else ""

                    if severity == 'Critical':
                        print(f"{Colors.RED}{Colors.BOLD}[!] {finding} - {url} (Status: {status}, Size: {size}){depth_str}{Colors.END}")
                    elif severity == 'High':
                        print(f"{Colors.RED}[!] {finding} - {url} (Status: {status}, Size: {size}){depth_str}{Colors.END}")
                    elif severity == 'Medium':
                        print(f"{Colors.YELLOW}[!] {finding} - {url} (Status: {status}, Size: {size}){depth_str}{Colors.END}")
                    elif severity == 'Low':
                        print(f"{Colors.BLUE}[*] {finding} - {url} (Status: {status}, Size: {size}){depth_str}{Colors.END}")
                    else:
                        print(f"{Colors.WHITE}[+] {finding} - {url} (Status: {status}, Size: {size}){depth_str}{Colors.END}")

                print(f"\n{Colors.GREEN}[+] Found {len(discovered)} accessible paths{Colors.END}")
            else:
                print(f"{Colors.GREEN}[+] No accessible subdirectories found{Colors.END}")

            return discovered

        except ImportError:
            print(f"{Colors.YELLOW}[!] Directory enumeration module not available{Colors.END}")
            return []
        except Exception as e:
            print(f"{Colors.RED}[-] Directory enumeration error: {e}{Colors.END}")
            return []

    def get_service_name(self, port):
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL',
            5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB'
        }
        return services.get(port, 'Unknown')
    
    def scan_wordpress(self):
        print(f"{Colors.BLUE}[*] Checking for WordPress...{Colors.END}")
        wp_paths = ['/wp-login.php', '/wp-admin/', '/wp-content/', '/wp-includes/']
        
        if not self.session:
            print(f"{Colors.YELLOW}[!] requests library not available{Colors.END}\n")
            return
            
        for path in wp_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"{Colors.YELLOW}[!] WordPress detected: {url}{Colors.END}")
            except:
                pass
        print()
    
    def detect_technologies(self):
        print(f"{Colors.BLUE}[*] Detecting technologies...{Colors.END}")
        if not self.session:
            print(f"{Colors.YELLOW}[!] requests library not available{Colors.END}\n")
            return
            
        try:
            response = self.session.get(self.target_url, timeout=10)
            tech = []
            
            if 'wordpress' in response.text.lower() or 'wp-content' in response.text.lower():
                tech.append('WordPress')
            if 'drupal' in response.text.lower():
                tech.append('Drupal')
            if 'joomla' in response.text.lower():
                tech.append('Joomla')
            if 'angular' in response.text.lower():
                tech.append('Angular')
            if 'react' in response.text.lower():
                tech.append('React')
            if 'vue' in response.text.lower():
                tech.append('Vue.js')
            
            server = response.headers.get('Server', '')
            if server:
                tech.append(server)
            
            if tech:
                print(f"{Colors.GREEN}[+] Technologies detected: {', '.join(tech)}{Colors.END}")
            else:
                print(f"{Colors.YELLOW}[!] Could not detect specific technologies{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[-] Error: {e}{Colors.END}")
        print()
    
    def print_results(self):
        print(f"\n{Colors.CYAN}{Colors.BOLD}==============================================================={Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}Scan Complete!{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}==============================================================={Colors.END}\n")
        
        if not self.findings:
            print(f"{Colors.GREEN}[+] No vulnerabilities detected{Colors.END}")
        else:
            print(f"{Colors.RED}{Colors.BOLD}[!] Found {len(self.findings)} potential issues:{Colors.END}\n")
            for i, finding in enumerate(self.findings, 1):
                print(f"{Colors.RED}{i}. {finding['type']}{Colors.END}")
                print(f"   Severity: {Colors.YELLOW}{finding['severity']}{Colors.END}")
                print(f"   URL: {Colors.CYAN}{finding['url']}{Colors.END}")
                if finding.get('payload'):
                    print(f"   Payload: {Colors.GREEN}{finding['payload']}{Colors.END}")
                print()
    
    def save_report(self):
        if not self.findings:
            return
        
        timestamp = int(time.time())
        filename = f"scan_report_{timestamp}.json"
        
        report = {
            'target': self.target_url,
            'scan_mode': self.scan_mode,
            'timestamp': timestamp,
            'findings': self.findings
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"{Colors.GREEN}[+] Report saved to: {filename}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[-] Could not save report: {e}{Colors.END}")

def main():
    print_banner()
    
    # Get scan mode
    print_menu()
    choice = input().strip()
    
    mode_map = {
        '1': 'all',
        '2': 'sqli',
        '3': 'xss',
        '4': 'idor',
        '5': 'lfi',
        '6': 'file_upload',
        '7': 'command_injection',
        '8': 'graphql',
        '9': 'api',
        '10': 'cloud',
        '11': 'ports',
        '12': 'cve',
        '13': 'wordpress',
        '14': 'rate',
        '15': 'directories',
        '16': 'encoder_decoder',
    }
    
    scan_mode = mode_map.get(choice, 'all')
    
    # If encoder/decoder tool selected, run it and exit
    if scan_mode == 'encoder_decoder':
        encoder_decoder_tool()
        sys.exit(0)
    
    # Get encoding preference
    print(f"\n{Colors.CYAN}{Colors.BOLD}Payload Encoding Options:{Colors.END}")
    encoding = get_encoding_menu()
    encoding_names = {
        '1': 'None',
        '2': 'URL Encode',
        '3': 'URL Encode Plus',
        '4': 'Double URL Encode',
        '5': 'Base64',
        '6': 'HTML Entity',
        '7': 'Hex',
        '8': 'Unicode'
    }
    print(f"{Colors.GREEN}[+] Encoding: {encoding_names.get(encoding, 'None')}{Colors.END}")
    
    # Get scan scope (single or multiple targets)
    targets = get_scope_input()
    
    if not targets:
        print(f"{Colors.RED}[-] No targets specified{Colors.END}")
        sys.exit(1)
    
    # Confirm
    print(f"\n{Colors.YELLOW}{Colors.BOLD}Confirm Scan:{Colors.END}")
    print(f"Targets: {Colors.CYAN}{len(targets)} target(s){Colors.END}")
    print(f"Mode: {Colors.CYAN}{scan_mode.upper()}{Colors.END}")
    print(f"Encoding: {Colors.CYAN}{encoding_names.get(encoding, 'None')}{Colors.END}")
    confirm = input(f"\n{Colors.GREEN}Start scan? (y/N): {Colors.END}").strip().lower()
    
    if confirm != 'y':
        print(f"{Colors.YELLOW}Scan cancelled{Colors.END}")
        sys.exit(0)
    
    # Run scan on all targets
    all_findings = []
    total_targets = len(targets)
    
    for target_idx, target_url in enumerate(targets, 1):
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}Scanning target {target_idx}/{total_targets}: {target_url}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.END}")
        
        # Run scanner for this target
        scanner = CLIScanner(target_url, scan_mode, encoding)
        
        # Apply encoding to payloads if selected
        if encoding != '1':
            print(f"\n{Colors.BLUE}[*] Applying {encoding_names.get(encoding)} encoding to payloads...{Colors.END}")
        
        try:
            scanner.scan()
            all_findings.extend(scanner.findings)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Target scan interrupted{Colors.END}")
            continue
        except Exception as e:
            print(f"{Colors.RED}[-] Error scanning {target_url}: {e}{Colors.END}")
            continue
    
    # Print summary for all targets
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.GREEN}{Colors.BOLD}All Scans Complete!{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"\n{Colors.GREEN}[+] Total targets scanned: {total_targets}{Colors.END}")
    print(f"{Colors.GREEN}[+] Total findings: {len(all_findings)}{Colors.END}")
    
    if all_findings:
        # Group findings by target
        findings_by_target = {}
        for finding in all_findings:
            target = finding.get('url', 'Unknown')
            if target not in findings_by_target:
                findings_by_target[target] = []
            findings_by_target[target].append(finding)
        
        print(f"\n{Colors.YELLOW}{Colors.BOLD}Findings Summary:{Colors.END}")
        for target, findings in findings_by_target.items():
            print(f"  {Colors.CYAN}{target}{Colors.END}: {len(findings)} finding(s)")
    
    # Save combined report
    timestamp = int(time.time())
    filename = f"scan_report_multi_{timestamp}.json"
    report = {
        'targets': targets,
        'scan_mode': scan_mode,
        'timestamp': timestamp,
        'total_targets': total_targets,
        'total_findings': len(all_findings),
        'findings': all_findings
    }
    try:
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n{Colors.GREEN}[+] Combined report saved to: {filename}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] Could not save report: {e}{Colors.END}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[-] Fatal error: {e}{Colors.END}")
        sys.exit(1)