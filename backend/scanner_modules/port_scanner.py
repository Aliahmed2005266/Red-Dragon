"""
Port Scanner Module - Detects open ports, service versions, authentication methods, and checks for CVEs
Enhanced with full port range scanning and comprehensive service detection
"""

import socket
import ssl
import re
from concurrent.futures import ThreadPoolExecutor, as_completed


class PortScanner:
    """
    Enhanced Port Scanner that:
    - Scans all ports (1-65535) or common ports
    - Detects port state: open, closed, or filtered
    - Performs banner grabbing for service version detection
    - Detects authentication methods for various services
    - Checks for known CVEs based on detected versions
    """

    def __init__(self, domain, scan_all=False):
        self.domain = domain
        self.scan_all = scan_all
        self.findings = []
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.scan_results = []

        # Resolve domain to IP for scanning
        try:
            self.ip_address = socket.gethostbyname(domain)
        except:
            self.ip_address = domain

        # Common ports with service names, version detection patterns, and auth detection
        self.common_ports = {
            21: {
                'service': 'FTP',
                'banner_re': rb'220[- ](.+)',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': b'',
                    'auth_banner_patterns': {
                        rb'230': 'Login successful',
                        rb'530': 'Authentication required',
                        rb'220': 'Banner only - try AUTH command'
                    }
                }
            },
            22: {
                'service': 'SSH',
                'banner_re': rb'SSH-[\d.]+\s+[-_a-zA-Z0-9]+[-_]([\d.pa-zA-Z]+)',
                'version_extract': r'([\d.]+p\d?)',
                'auth_methods': {
                    'detection_probe': b'',
                    'auth_banner_patterns': {
                        rb'SSH-': 'Key-based / Password'
                    }
                }
            },
            23: {
                'service': 'Telnet',
                'banner_re': rb'(?:Welcome|Connected|ready|[\w-_]+ Telnet)[^\n]*',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': b'\xff\xfb\x01\xff\xfb\x03',
                    'auth_banner_patterns': {
                        rb'login:': 'Username/Password authentication',
                        rb'password:': 'Password authentication',
                        rb'Welcome': 'No authentication (open)',
                    }
                }
            },
            25: {
                'service': 'SMTP',
                'banner_re': rb'220[- ][^\n]*',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': b'EHLO scanner.local\r\n',
                    'auth_banner_patterns': {
                        rb'250-AUTH': 'AUTH supported',
                        rb'250-STARTTLS': 'STARTTLS available',
                        rb'PLAIN': 'PLAIN authentication',
                        rb'LOGIN': 'LOGIN authentication',
                        rb'CRAM-MD5': 'CRAM-MD5 authentication',
                    }
                }
            },
            53: {
                'service': 'DNS',
                'banner_re': None,
                'version_extract': None,
                'auth_methods': {
                    'detection_probe': None,
                    'auth_banner_patterns': {}
                }
            },
            80: {
                'service': 'HTTP',
                'banner_re': rb'Server: (.+)',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': None,
                    'auth_banner_patterns': {
                        rb'401': 'HTTP Basic/Digest authentication',
                        rb'WWW-Authenticate: Basic': 'HTTP Basic authentication',
                        rb'WWW-Authenticate: Digest': 'HTTP Digest authentication',
                        rb'WWW-Authenticate: Bearer': 'OAuth/Bearer token authentication',
                        rb'200': 'No authentication required',
                    }
                }
            },
            110: {
                'service': 'POP3',
                'banner_re': rb'\+OK[^\n]*',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': b'',
                    'auth_banner_patterns': {
                        rb'\+OK': 'USER/PASS authentication',
                        rb'APOP': 'APOP authentication',
                    }
                }
            },
            135: {
                'service': 'RPC',
                'banner_re': None,
                'version_extract': None,
                'auth_methods': {}
                        },
            143: {
                'service': 'IMAP',
                'banner_re': rb'\* OK[^\n]*',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': b'a1 CAPABILITY\r\n',
                    'auth_banner_patterns': {
                        rb'CAPABILITY': 'IMAP capabilities available',
                        rb'LOGIN': 'LOGIN authentication',
                        rb'PLAIN': 'PLAIN authentication',
                        rb'CRAM-MD5': 'CRAM-MD5 authentication',
                        rb'NTLM': 'NTLM authentication',
                    }
                }
            },
            443: {
                'service': 'HTTPS',
                'banner_re': rb'Server: (.+)',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': None,
                    'auth_banner_patterns': {
                        rb'401': 'HTTPS Basic/Digest authentication',
                        rb'WWW-Authenticate: Basic': 'HTTPS Basic authentication',
                        rb'WWW-Authenticate: Digest': 'HTTPS Digest authentication',
                        rb'WWW-Authenticate: Bearer': 'OAuth/Bearer token authentication',
                        rb'200': 'No authentication required',
                    }
                }
            },
            445: {
                'service': 'SMB',
                'banner_re': None,
                'version_extract': None,
                'auth_methods': {
                    'detection_probe': b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00',
                    'auth_banner_patterns': {
                        rb'NTLMSSP': 'NTLM authentication',
                                                rb'Kerberos': 'Kerberos authentication',
                    }
                }
            },
            993: {
                'service': 'IMAPS',
                'banner_re': rb'\* OK[^\n]*',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': b'',
                    'auth_banner_patterns': {
                        rb'\+OK': 'SSL/TLS + Login authentication',
                    }
                }
            },
            995: {
                'service': 'POP3S',
                'banner_re': rb'\+OK[^\n]*',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': b'',
                    'auth_banner_patterns': {
                        rb'\+OK': 'SSL/TLS + Login authentication',
                    }
                }
            },
            1433: {
                'service': 'MSSQL',
                'banner_re': None,
                'version_extract': None,
                'auth_methods': {
                    'detection_probe': b'\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00',
                    'auth_banner_patterns': {
                        rb'MSSQLServer': 'SQL Server authentication',
                                                rb'Login failed': 'Login failed - auth required',
                        rb'NTLM': 'NTLM authentication',
                    }
                }
            },
            1521: {
                'service': 'Oracle',
                'banner_re': None,
                'version_extract': None,
                'auth_methods': {
                    'detection_probe': b'\x00\x5a\x00\x00\x01\x00\x00\x00\x01\x36\x01\x2c\x00\x00\x08\x00\x7f\xff\x7f\x08\x00\x00\x00\x01\x00\x20\x00\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x34\xe6\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x28\x43\x4f\x4e\x4e\x45\x43\x54\x5f\x44\x41\x54\x41\x3d\x28\x43\x4f\x4d\x4d\x41\x4e\x44\x3d\x76\x65\x72\x73\x69\x6f\x6e\x29\x29',
                    'auth_banner_patterns': {
                        rb'Oracle': 'Oracle authentication required',
                                                rb'TNS': 'TNS authentication',
                    }
                }
            },
            3306: {
                'service': 'MySQL',
                'banner_re': rb'[\d.]+-MariaDB|[\d.]+-log|mysql[\d.]+|Server version:[\s]*([\d.]+)',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': b'',
                    'auth_banner_patterns': {
                        rb'mysql_native_password': 'Native password authentication',
                        rb'caching_sha2_password': 'SHA2 password authentication',
                        rb'Access denied': 'Authentication required',
                    }
                }
            },
            3389: {
                'service': 'RDP',
                'banner_re': None,
                'version_extract': None,
                'auth_methods': {
                    'detection_probe': b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00',
                    'auth_banner_patterns': {
                        rb'\x03\x00\x00': 'RDP authentication required',
                    }
                }
            },
            5432: {
                'service': 'PostgreSQL',
                'banner_re': rb'(\d[\d.]+\d)',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': b'\x00\x00\x00\x08\x0d\x22\x16\x2f',
                    'auth_banner_patterns': {
                        rb'R\x00\x00\x00\x08\x00\x00\x00\x03': 'MD5 password authentication',
                        rb'AuthenticationCleartextPassword': 'Cleartext password',
                        rb'AuthenticationMD5Password': 'MD5 password',
                                                rb'SASL': 'SASL authentication',
                    }
                }
            },
            5900: {
                'service': 'VNC',
                'banner_re': rb'RFB ([\d.]+)',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': b'RFB 003.008\n',
                    'auth_banner_patterns': {
                        rb'RFB': 'VNC authentication required',
                        rb'None': 'No authentication (open VNC)',
                        rb'VNC Authentication': 'VNC password authentication',
                    }
                }
            },
            5901: {
                'service': 'VNC-1',
                'banner_re': rb'RFB ([\d.]+)',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': b'RFB 003.008\n',
                    'auth_banner_patterns': {
                        rb'RFB': 'VNC authentication required',
                        rb'None': 'No authentication (open VNC)',
                        rb'VNC Authentication': 'VNC password authentication',
                    }
                }
            },
            6379: {
                'service': 'Redis',
                'banner_re': rb'([\d.]+)',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': b'*1\r\n$4\r\nPING\r\n',
                    'auth_banner_patterns': {
                        rb'NOAUTH': 'Authentication required (password)',
                        rb'PONG': 'No authentication (open Redis)',
                                                rb'LOADING': 'Redis loading - auth required',
                    }
                }
            },
            8080: {
                'service': 'HTTP-Proxy',
                'banner_re': rb'Server: (.+)',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': None,
                    'auth_banner_patterns': {
                        rb'407': 'Proxy authentication required',
                        rb'401': 'HTTP authentication required',
                        rb'200': 'No authentication required',
                    }
                }
            },
            8443: {
                'service': 'HTTPS-Alt',
                'banner_re': rb'Server: (.+)',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': None,
                    'auth_banner_patterns': {
                        rb'401': 'HTTPS authentication required',
                        rb'200': 'No authentication required',
                    }
                }
            },
            27017: {
                'service': 'MongoDB',
                'banner_re': None,
                'version_extract': None,
                'auth_methods': {
                    'detection_probe': b'\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00',
                    'auth_banner_patterns': {
                        rb'unauthorized': 'Authentication required',
                        rb'SCRAM-SHA-1': 'SCRAM-SHA-1 authentication',
                        rb'SCRAM-SHA-256': 'SCRAM-SHA-256 authentication',
                    }
                }
            },
            8888: {
                'service': 'HTTP-Alt',
                'banner_re': rb'Server: (.+)',
                'version_extract': r'([\d.]+)',
                'auth_methods': {
                    'detection_probe': None,
                    'auth_banner_patterns': {
                        rb'401': 'HTTP authentication required',
                        rb'200': 'No authentication required',
                    }
                }
            },
            9200: {
                'service': 'Elasticsearch',
                'banner_re': None,
                'version_extract': None,
                'auth_methods': {
                    'detection_probe': None,
                    'auth_banner_patterns': {
                        rb'401': 'Elasticsearch authentication required',
                        rb'unauthorized': 'Authentication required',
                    }
                }
            },
            11211: {
                'service': 'Memcached',
                'banner_re': None,
                'version_extract': None,
                'auth_methods': {
                    'detection_probe': b'stats\r\n',
                    'auth_banner_patterns': {
                        rb'STATS': 'No authentication (open Memcached)',
                        rb'ERROR': 'Error - may require auth',
                        rb'AUTH': 'SASL authentication required',
                    }
                }
            },
        }
        
        # All well-known ports (1-1024) for comprehensive scanning
        self.all_well_known_ports = list(range(1, 1025))
        
        # Extended port range (1-65535) for full scan
        self.all_ports = list(range(1, 65536))
        
        # Service name mapping for ports not in common_ports
        self.port_service_map = {
            7: 'Echo', 9: 'Discard', 11: 'Systat', 13: 'Daytime', 17: 'Qotd',
            19: 'Chargen', 37: 'Time', 42: 'Nameserver', 43: 'Whois', 53: 'DNS',
            67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 70: 'Gopher', 79: 'Finger',
            88: 'Kerberos', 111: 'RPCBind', 113: 'Ident',
            119: 'NNTP', 123: 'NTP', 137: 'NetBIOS-NS', 138: 'NetBIOS-DGM',
            161: 'SNMP', 162: 'SNMP-Trap', 177: 'XDMCP', 179: 'BGP',
            194: 'IRC', 201: 'AppleTalk', 264: 'BGMP', 318: 'TSP',
            381: 'HP-OpenView', 383: 'HP-OpenView', 444: 'SNPP',
            464: 'Kerberos-Change', 465: 'SMTPS', 497: 'Retrospect',
            500: 'ISAKMP', 512: 'rexec', 513: 'rlogin', 514: 'syslog',
            515: 'LPD', 520: 'RIP', 521: 'RIPng', 524: 'NCP', 530: 'RPC',
            531: 'AIM', 532: 'netnews', 540: 'UUCP', 543: 'KLogin',
            544: 'KShell', 546: 'DHCPv6-Client', 547: 'DHCPv6-Server',
            548: 'AFP', 554: 'RTSP', 556: 'Remotefs', 563: 'NNTPS',
            587: 'SMTP-Sub', 591: 'FileMaker', 593: 'HTTP-RPC', 631: 'IPP',
            636: 'LDAPS', 639: 'MSDP', 646: 'LDP', 648: 'RRS', 652: 'DTCP',
            654: 'AODV', 666: 'Doom', 674: 'ACAP', 691: 'MS-Exchange',
            699: 'AccessNetwork', 700: 'EPP', 705: 'AgentX', 711: 'TDP',
            714: 'IRCS', 720: 'SMQP', 722: 'SGCP', 749: 'Kerberos-Admin',
            750: 'Kerberos-IV', 782: 'Consul', 783: 'SpamAssassin',
            800: 'MDBS-Daemon', 808: 'CCProxy', 814: 'OpeNMS', 829: 'PKIX',
            830: 'NETCONF-SSH', 831: 'NETCONF-Beep', 832: 'NETCONF-HTTPS',
            833: 'NETCONF-SOAP', 843: 'AdobeFlash', 847: 'DHCP-Failover',
            848: 'GDOI', 860: 'iSCSI', 861: 'OWAMP-Control',
            862: 'TWAMP-Control', 873: 'Rsync', 888: 'CDDBP', 898: 'Sun-Web',
            902: 'VMware', 903: 'VMware', 953: 'RNDC', 981: 'SofaWare',
            987: 'SharePoint', 989: 'FTPS-Data', 990: 'FTPS',
                    }

    def scan_port(self, port, timeout=3):
        """
        Scan a single port and detect:
        - Port state: open, closed, or filtered
        - Service version via banner grabbing
        - Authentication method
        """
        result = {
            'port': port,
            'is_open': False,
            'status': 'closed',
            'service': self.common_ports.get(port, {}).get('service') or self.port_service_map.get(port, 'Unknown'),
            'version': None,
            'banner': None,
            'auth_method': None,
            'error': None
        }

        try:
            # TCP connect scan
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result_code = sock.connect_ex((self.domain, port))

            if result_code == 0:
                # Port is open
                result['is_open'] = True
                result['status'] = 'open'

                # Grab banner and detect version + auth
                port_info = self.common_ports.get(port, {})
                banner, version, auth = self._grab_banner(sock, port, port_info, timeout)
                result['banner'] = banner
                result['version'] = version
                result['auth_method'] = auth

            elif result_code in (10060, 110):
                # Connection timed out - port is filtered
                result['status'] = 'filtered'
                result['error'] = f'Connection timed out (errno: {result_code})'

            elif result_code in (111, 10061):
                # Connection refused - port is closed
                result['status'] = 'closed'
                result['error'] = f'Connection refused (errno: {result_code})'

            else:
                # Other error - treat as filtered
                result['status'] = 'filtered'
                result['error'] = f'Error: {result_code}'

            sock.close()

        except socket.timeout:
            result['status'] = 'filtered'
            result['error'] = 'Timeout - port may be filtered'
        except ConnectionRefusedError:
            result['status'] = 'closed'
            result['error'] = 'Connection refused'
        except Exception as e:
            result['error'] = str(e)

        return result

    def _grab_banner(self, sock, port, port_info, timeout=3):
        """
        Grab service banner from an open port for version and auth detection.
        """
        banner = None
        version = None
        auth_method = None
        auth_data = port_info.get('auth_methods', {})

        # First, try to receive banner sent by the service (passive grab)
        try:
            sock.settimeout(timeout)
            banner_data = sock.recv(4096)
            if banner_data:
                banner = banner_data
        except socket.timeout:
            pass
        except Exception:
            pass

        # If no banner received, send a probe and try to get a response
        if not banner and auth_data.get('detection_probe'):
            try:
                sock.settimeout(timeout)
                probe = auth_data.get('detection_probe')
                if probe:
                    sock.sendall(probe)
                    banner_data = sock.recv(4096)
                    if banner_data:
                        banner = banner_data
            except (socket.timeout, Exception):
                pass

        # Special handling for HTTP/HTTPS ports (443, 8443)
        if port in [443, 8443]:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                ssl_sock = context.wrap_socket(sock, server_hostname=self.domain)
                ssl_sock.settimeout(timeout)

                host_header = self.domain.encode()
                http_request = b'HEAD / HTTP/1.1\r\nHost: ' + host_header + b'\r\nConnection: close\r\n\r\n'
                ssl_sock.sendall(http_request)
                ssl_response = ssl_sock.recv(4096)
                if ssl_response:
                    if banner:
                        banner += b'\r\n' + ssl_response
                    else:
                        banner = ssl_response
                    auth_method = self._parse_http_auth(ssl_response)
                    if not version:
                        version = self._detect_version(banner, port_info)
                ssl_sock.close()
            except Exception:
                pass

        # For HTTP ports, send HTTP request if no banner
        if port in [80, 8080, 8888, 9200] and not banner:
            try:
                host_header = self.domain.encode()
                http_request = b'HEAD / HTTP/1.1\r\nHost: ' + host_header + b'\r\nConnection: close\r\n\r\n'
                sock.sendall(http_request)
                http_response = sock.recv(4096)
                if http_response:
                    banner = http_response
                    auth_method = self._parse_http_auth(http_response)
            except Exception:
                pass

        # Detect version from banner
        if not version:
            version = self._detect_version(banner, port_info)

        # Detect authentication method from banner/response
        if not auth_method:
            auth_method = self._detect_auth_method(banner, port_info)

        return banner, version, auth_method

    def _parse_http_auth(self, http_response):
        """Parse HTTP response headers for authentication methods."""
        if not http_response:
            return None
        try:
            response_str = http_response.decode('utf-8', errors='ignore')
            auth_header = re.search(r'WWW-Authenticate:\s*(.+)', response_str, re.IGNORECASE)
            if auth_header:
                auth_value = auth_header.group(1).strip()
                return auth_value.split(',')[0]

            status_match = re.match(r'HTTP/\d\.\d\s+(\d+)', response_str)
            if status_match:
                status_code = status_match.group(1)
                if status_code == '401':
                    return 'Basic/Digest authentication required'
                elif status_code == '407':
                    return 'Proxy authentication required'
                elif status_code == '200':
                    return 'No authentication required'
        except Exception:
            pass
        return None

    def _detect_version(self, banner, port_info):
        """Extract version information from the banner using service-specific patterns."""
        if not banner or not port_info.get('banner_re'):
            if banner:
                banner_str = banner.decode('utf-8', errors='ignore')
                version_patterns = [
r'Version[\s:]+([\d.]+[\w\-]*)',
                    r'version[\s\-]+([\d.]+[\w\-]*)',
                    r'v([\d]+\.[\d]+\.[\d]+)',
                    r'(\d+\.\d+\.\d+[\w\-\.]*)',
                ]
                for pattern in version_patterns:
                    match = re.search(pattern, banner_str, re.IGNORECASE)
                    if match:
                        return match.group(1)
            return None

    def _detect_auth_method(self, banner, port_info):
        """Detect the authentication method used by the service based on the banner."""
        if not banner:
            return None

        auth_data = port_info.get('auth_methods', {})
        auth_patterns = auth_data.get('auth_banner_patterns', {})

        banner_str = banner.decode('utf-8', errors='ignore')
        banner_raw = banner

        # Check each auth pattern against the banner
        for pattern, description in auth_patterns.items():
            try:
                pattern_str = pattern.decode('utf-8', errors='ignore')
            except Exception:
                continue

            if pattern in banner_raw:
                return description
            if pattern_str in banner_str:
                return description

        # General auth detection for HTTP services
        if port_info.get('service') in ('HTTP', 'HTTP-Proxy', 'HTTP-Alt', 'HTTPS-Alt'):
            status_match = re.search(r'HTTP/\d\.\d\s+(\d+)', banner_str)
            if status_match:
                code = status_match.group(1)
                if code == '401':
                    return 'HTTP authentication required'
                elif code == '200':
                    return 'No authentication required'

        # Redis: check for NOAUTH/PONG responses
        if port_info.get('service') == 'Redis':
            if b'NOAUTH' in banner_raw:
                return 'Authentication required (password)'
            if b'PONG' in banner_raw:
                return 'No authentication (open)'

        # PostgreSQL: check for auth response codes
        if port_info.get('service') == 'PostgreSQL':
            idx = banner_raw.find(b'\x00\x00\x00\x08')
            if idx != -1 and len(banner_raw) > idx + 5:
                auth_byte = banner_raw[idx + 5]
                if auth_byte == 0:
                    return 'Trust authentication'
                elif auth_byte == 3:
                    return 'MD5 password authentication'
                elif auth_byte == 5:
                    return 'SCM credential authentication'
                elif auth_byte == 10:
                    return 'SASL authentication'
                elif auth_byte == 11:
                    return 'GSSAPI authentication'

        # MongoDB: check for response
        if port_info.get('service') == 'MongoDB':
            if b'unauthorized' in banner_raw:
                return 'Authentication required'
            if b'ok' in banner_raw:
                return 'No authentication (open)'

        # Memcached: check for response
        if port_info.get('service') == 'Memcached':
            if b'STATS' in banner_raw:
                return 'No authentication (open)'
            if b'AUTH' in banner_raw:
                return 'SASL authentication required'

        return None

    def _check_ftp_anonymous(self, sock):
        """Check if FTP service allows anonymous login."""
        try:
            sock.settimeout(3)
            sock.sendall(b'USER anonymous\r\n')
            response1 = sock.recv(1024)
            if b'331' in response1 or b'230' in response1:
                sock.sendall(b'PASS anonymous\r\n')
                response2 = sock.recv(1024)
                if b'230' in response2:
                    return 'Anonymous login allowed (HIGH RISK)'
            return None
        except Exception:
            return None

    def _check_port_cves(self, port_info):
        """Check for known CVEs based on detected service version."""
        cve_findings = []
        port = port_info.get('port')
        version = port_info.get('version')
        service = port_info.get('service', '')

        if not version:
            return cve_findings

        # Determine actual software name from banner/service for accurate CVE matching
        # Generic service names (HTTP, SSH, FTP) don't match CVE software names (Apache, nginx, OpenSSH)
        banner_str = port_info.get('banner', b'').decode('utf-8', errors='ignore') if port_info.get('banner') else ''
        software = service  # fallback to generic service name
        # Try to extract specific software from banner
        banner_lower = banner_str.lower()
        if 'apache' in banner_lower:
            software = 'Apache'
        elif 'nginx' in banner_lower:
            software = 'nginx'
        elif 'openssh' in banner_lower or 'ssh-' in banner_lower:
            software = 'OpenSSH'
        elif 'vsftpd' in banner_lower:
            software = 'vsftpd'
        elif 'proftpd' in banner_lower:
            software = 'ProFTPD'
        elif 'mysql' in banner_lower:
            software = 'MySQL'
        elif 'postgres' in banner_lower:
            software = 'PostgreSQL'
        elif 'redis' in banner_lower:
            software = 'Redis'
        elif 'mongodb' in banner_lower:
            software = 'MongoDB'
        elif 'memcached' in banner_lower:
            software = 'Memcached'
        cve_data = self._get_cve_data()

        for cve in cve_data:
            if cve['software'].lower() in software.lower() or software.lower() in cve['software'].lower():
                affected = cve['affected']
                try:
                    if affected.startswith('<='):
                        threshold = affected[2:]
                        if version and self._compare_versions(version, threshold) <= 0:
                            cve_findings.append({
                                'type': 'CVE',
                                'severity': cve['severity'],
                                'title': f"Known CVE for {software}: {cve['cve']}",
                                'description': f"{cve['description']}. Affects {software} version {affected}. Detected: {version}",
                                'port': port,
                                'service': service,
                                'software': software,
                                'version': version,
                                'cve_id': cve['cve'],
                                'remediation': f"Update {software} to latest secure version. Apply vendor security patches."
                            })
                    elif affected.startswith('<'):
                        threshold = affected[1:]
                        if version and self._compare_versions(version, threshold) < 0:
                            cve_findings.append({
                                'type': 'CVE',
                                'severity': cve['severity'],
                                'title': f"Known CVE for {software}: {cve['cve']}",
                                'description': f"{cve['description']}. Affects {software} versions {affected}. Detected: {version}",
                                'port': port,
                                'service': service,
                                'software': software,
                                'version': version,
                                'cve_id': cve['cve'],
                                'remediation': f"Update {software} to latest secure version. Apply vendor security patches."
                            })
                except Exception:
                    continue

        return cve_findings

    def _get_cve_data(self):
        """Return known CVE data for services."""
        return [
            {'software': 'OpenSSH', 'cve': 'CVE-2023-48795', 'severity': 'High',
             'affected': '<9.6', 'description': 'Terrapin attack - allows prefix injection in SSH protocol'},
            {'software': 'OpenSSH', 'cve': 'CVE-2023-48794', 'severity': 'High',
             'affected': '<9.6', 'description': 'Remote code execution via ssh-agent'},
            {'software': 'vsftpd', 'cve': 'CVE-2011-2523', 'severity': 'Critical',
             'affected': '<2.3.5', 'description': 'Backdoor command execution'},
            {'software': 'ProFTPD', 'cve': 'CVE-2015-3306', 'severity': 'Critical',
             'affected': '<1.3.5', 'description': 'Remote code execution via mod_copy module'},
            {'software': 'MySQL', 'cve': 'CVE-2021-21540', 'severity': 'High',
             'affected': '<8.0.23', 'description': 'Privilege escalation in MySQL'},
            {'software': 'Redis', 'cve': 'CVE-2022-0543', 'severity': 'High',
             'affected': '<6.2.6', 'description': 'Remote code execution via Lua scripting'},
            {'software': 'Redis', 'cve': 'CVE-2015-4445', 'severity': 'High',
             'affected': '<3.0.0', 'description': 'Remote code execution'},
            {'software': 'MongoDB', 'cve': 'CVE-2018-6578', 'severity': 'High',
             'affected': '<3.6.5', 'description': 'Remote code execution'},
            {'software': 'PostgreSQL', 'cve': 'CVE-2017-7525', 'severity': 'High',
             'affected': '<10.1', 'description': 'Remote code execution'},
        ]

    def _compare_versions(self, v1, v2):
        """Compare version strings, returns -1, 0, or 1."""
        try:
            v1_parts = [int(x) for x in re.findall(r'\d+', v1)]
            v2_parts = [int(x) for x in re.findall(r'\d+', v2)]
            for i in range(max(len(v1_parts), len(v2_parts))):
                v1_val = v1_parts[i] if i < len(v1_parts) else 0
                v2_val = v2_parts[i] if i < len(v2_parts) else 0
                if v1_val < v2_val:
                    return -1
                elif v1_val > v2_val:
                    return 1
            return 0
        except Exception:
            return 0

    def scan(self, ports=None, timeout=3, scan_all=None):
        """
        Scan ports with version detection and auth method detection.
        
        Args:
            ports: List of specific ports to scan. If None, uses common_ports.
            timeout: Connection timeout in seconds per port.
            scan_all: If True, scan all ports (1-65535). If None, uses
                      self.scan_all from the constructor.
        
        Returns:
            List of open port results with service version and auth method info.
        """
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.scan_results = []

        # Resolve scan_all: explicit parameter overrides constructor setting
        if scan_all is None:
            scan_all = self.scan_all

        if scan_all:
            # Full port range scan (1-65535)
            ports_to_scan = self.all_ports
        elif ports is None:
            ports_to_scan = list(self.common_ports.keys())
        else:
            ports_to_scan = ports

        # Use thread pool for faster scanning
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self.scan_port, port, timeout): port for port in ports_to_scan}

            for future in as_completed(futures):
                result = future.result()
                self.scan_results.append(result)

                if result['status'] == 'open':
                    self.open_ports.append(result)
                elif result['status'] == 'closed':
                    self.closed_ports.append(result)
                elif result['status'] == 'filtered':
                    self.filtered_ports.append(result)

        # Process open ports: check for CVEs and add findings
        for port_info in self.open_ports:
            if port_info.get('version'):
                cve_findings = self._check_port_cves(port_info)
                self.findings.extend(cve_findings)

            # Add info finding about open port
            version_str = f" (v{port_info['version']})" if port_info.get('version') else ""
            banner_preview = ""
            if port_info.get('banner'):
                try:
                    banner_preview = f" - {port_info['banner'][:80]}"
                except Exception:
                    banner_preview = ""

            finding = {
                'type': 'Network',
                'severity': 'Info',
                'title': f"Port {port_info['port']}/{port_info['service']} is open{version_str}",
                'description': f"Port {port_info['port']} ({port_info['service']}) is {port_info['status']}{version_str}.{banner_preview}",
                'port': port_info['port'],
                'service': port_info.get('service', 'Unknown'),
                'version': port_info.get('version', 'Unknown'),
                'auth_method': port_info.get('auth_method') or 'Not determined',
            }

            # Flag high-risk auth methods
            auth = port_info.get('auth_method')
            if auth:
                if 'No authentication' in auth or 'open' in auth.lower():
                    finding['severity'] = 'High'
                    finding['title'] += ' - No Authentication (VULNERABLE)'
                    finding['description'] += f" Auth: {auth}"
                    finding['remediation'] = 'This service requires NO authentication and is accessible. Restrict access immediately.'
                elif 'Authentication required' in auth:
                    finding['severity'] = 'Medium'
                    finding['description'] += f" Auth: {auth}"
                    finding['remediation'] = 'Ensure strong authentication is configured for this service.'
                else:
                    finding['description'] += f" Auth: {auth}"

            if not auth:
                finding['remediation'] = 'Close unnecessary ports. Ensure services are properly configured and up-to-date.'

            self.findings.append(finding)

        return self.open_ports