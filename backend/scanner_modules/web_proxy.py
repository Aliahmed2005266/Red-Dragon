"""
Web Proxy & Interceptor Module - Burp Suite-like request interception and modification
"""

import threading
import json
import time
import re
from urllib.parse import urlparse, urlencode, parse_qs
import base64

class RequestInterceptor:
    """Intercepts, displays, and allows modification of HTTP requests"""
    
    def __init__(self):
        self.intercepted_requests = []
        self.intercepted_responses = []
        self.intercept_enabled = True
        self.modify_enabled = True
        self.max_history = 500
        self.request_id = 0
        self._lock = threading.Lock()
        
        # Common patterns to highlight
        self.sensitive_patterns = [
            'password', 'secret', 'token', 'auth', 'api_key', 'apikey',
            'authorization', 'bearer', 'jwt', 'session', 'cookie',
            'csrf', 'xsrf', 'credit_card', 'ssn', 'pin',
        ]
    
    def capture_request(self, method, url, headers, body=None, source='browser'):
        """Capture and log a request for interception"""
        with self._lock:
            self.request_id += 1
            request = {
                'id': self.request_id,
                'timestamp': time.strftime('%H:%M:%S.%f')[:-3],
                'method': method.upper(),
                'url': url,
                'headers': dict(headers),
                'body': body,
                'source': source,
                'status': 'pending',
                'modified': False,
                'original': {
                    'method': method.upper(),
                    'url': url,
                    'headers': dict(headers),
                    'body': body,
                }
            }
            
            # Auto-highlight sensitive data
            request['sensitive'] = self._detect_sensitive(body) if body else []
            if headers:
                for k, v in headers.items():
                    if any(s in k.lower() for s in self.sensitive_patterns):
                        request['sensitive'].append(f"Header: {k}")
            
            self.intercepted_requests.append(request)
            
            # Trim history
            if len(self.intercepted_requests) > self.max_history:
                self.intercepted_requests = self.intercepted_requests[-self.max_history:]
            
            return request['id']
    
    def capture_response(self, request_id, status_code, headers, body=None):
        """Capture and log the response for a request"""
        with self._lock:
            response = {
                'request_id': request_id,
                'timestamp': time.strftime('%H:%M:%S.%f')[:-3],
                'status_code': status_code,
                'headers': dict(headers),
                'body': body,
                'size': len(body) if body else 0,
                'sensitive': []
            }
            
            # Detect sensitive data in response
            if body:
                response['sensitive'] = self._detect_sensitive(body)
            
            self.intercepted_responses.append(response)
            
            # Update the request status
            for req in self.intercepted_requests:
                if req['id'] == request_id:
                    req['status'] = 'completed'
                    req['response_status'] = status_code
                    req['response_size'] = len(body) if body else 0
            
            # Trim history
            if len(self.intercepted_responses) > self.max_history:
                self.intercepted_responses = self.intercepted_responses[-self.max_history:]
    
    def modify_request(self, request_id, method=None, url=None, headers=None, body=None):
        """Modify a captured request before sending"""
        with self._lock:
            for req in self.intercepted_requests:
                if req['id'] == request_id:
                    if method:
                        req['method'] = method.upper()
                    if url:
                        req['url'] = url
                    if headers:
                        req['headers'] = headers
                    if body is not None:
                        req['body'] = body
                    req['modified'] = True
                    req['status'] = 'modified'
                    return True
            return False
    
    def replay_request(self, request_id, modifications=None):
        """Replay a captured/modified request"""
        req = None
        with self._lock:
            for r in self.intercepted_requests:
                if r['id'] == request_id:
                    req = r.copy()
                    break
        
        if not req:
            return None
        
        # Apply any additional modifications
        if modifications:
            if 'method' in modifications:
                req['method'] = modifications['method']
            if 'url' in modifications:
                req['url'] = modifications['url']
            if 'headers' in modifications:
                req['headers'] = modifications['headers']
            if 'body' in modifications:
                req['body'] = modifications['body']
        
        # Send the request
        import requests as req_lib
        try:
            session = req_lib.Session()
            
            # Parse headers
            headers = req.get('headers', {})
            
            # Send based on method
            method = req.get('method', 'GET').upper()
            url = req.get('url', '')
            body = req.get('body')
            
            start_time = time.time()
            
            if method == 'GET':
                response = session.get(url, headers=headers, timeout=30, allow_redirects=False)
            elif method == 'POST':
                response = session.post(url, headers=headers, data=body, timeout=30, allow_redirects=False)
            elif method == 'PUT':
                response = session.put(url, headers=headers, data=body, timeout=30, allow_redirects=False)
            elif method == 'DELETE':
                response = session.delete(url, headers=headers, timeout=30, allow_redirects=False)
            elif method == 'PATCH':
                response = session.patch(url, headers=headers, data=body, timeout=30, allow_redirects=False)
            elif method == 'OPTIONS':
                response = session.options(url, headers=headers, timeout=30, allow_redirects=False)
            elif method == 'HEAD':
                response = session.head(url, headers=headers, timeout=30, allow_redirects=False)
            else:
                response = session.request(method, url, headers=headers, data=body, timeout=30, allow_redirects=False)
            
            elapsed = time.time() - start_time
            
            result = {
                'request_id': request_id,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text,
                'size': len(response.text),
                'time': f'{elapsed:.2f}s',
                'request': {
                    'method': method,
                    'url': url,
                    'headers': headers,
                    'body': body,
                }
            }
            
            return result
            
        except Exception as e:
            return {'error': str(e), 'request_id': request_id}
    
    def get_history(self, limit=50):
        """Get request/response history"""
        with self._lock:
            history = []
            for req in self.intercepted_requests[-limit:]:
                item = {
                    'id': req['id'],
                    'timestamp': req['timestamp'],
                    'method': req['method'],
                    'url': req['url'],
                    'status': req.get('status', 'unknown'),
                    'response_status': req.get('response_status', '-'),
                    'response_size': req.get('response_size', 0),
                    'modified': req.get('modified', False),
                    'sensitive': req.get('sensitive', []),
                }
                
                # Find corresponding response
                for resp in self.intercepted_responses:
                    if resp['request_id'] == req['id']:
                        item['response'] = {
                            'status_code': resp['status_code'],
                            'size': resp['size'],
                        }
                        break
                
                history.append(item)
            
            return history
    
    def get_request_detail(self, request_id):
        """Get full details of a request and its response"""
        req = None
        resp = None
        
        with self._lock:
            for r in self.intercepted_requests:
                if r['id'] == request_id:
                    req = r.copy()
                    break
            
            for r in self.intercepted_responses:
                if r['request_id'] == request_id:
                    resp = r.copy()
                    break
        
        return {
            'request': req,
            'response': resp,
        }
    
    def _detect_sensitive(self, text):
        """Detect sensitive data patterns in text"""
        if not text:
            return []
        
        found = []
        patterns = {
            'API Key': r'(?i)(?:api[_-]?key|apikey)[=:]["\' ]?([a-zA-Z0-9_\-]{16,64})',
            'JWT Token': r'(?i)eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}',
            'Bearer Token': r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}',
            'Password': r'(?i)(?:password|passwd|pwd)[=:]["\' ]?([^\s&"\']+)',
            'Secret': r'(?i)(?:secret)[=:]["\' ]?([a-zA-Z0-9_\-]{8,})',
            'Credit Card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'IP Address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'Private Key': r'-----BEGIN.*?PRIVATE KEY-----',
        }
        
        for name, pattern in patterns.items():
            if re.search(pattern, str(text)):
                found.append(name)
        
        return found
    
    def search_requests(self, query):
        """Search through intercepted requests"""
        results = []
        with self._lock:
            for req in self.intercepted_requests:
                search_text = json.dumps({
                    'method': req['method'],
                    'url': req['url'],
                    'headers': req['headers'],
                    'body': req.get('body', ''),
                })
                if query.lower() in search_text.lower():
                    results.append({
                        'id': req['id'],
                        'method': req['method'],
                        'url': req['url'],
                        'timestamp': req['timestamp'],
                    })
        return results
    
    def toggle_intercept(self):
        """Toggle interception on/off"""
        self.intercept_enabled = not self.intercept_enabled
        return self.intercept_enabled
    
    def clear_history(self):
        """Clear all intercepted data"""
        with self._lock:
            self.intercepted_requests = []
            self.intercepted_responses = []
        return True


class NetworkCapture:
    """Network traffic capture module (Wireshark-like)"""
    
    def __init__(self):
        self.packets = []
        self.capturing = False
        self._lock = threading.Lock()
        self.max_packets = 1000
        self.packet_id = 0
        self.filters = []
    
    def start_capture(self):
        """Start network capture monitoring"""
        self.capturing = True
        self.packets = []
        self.packet_id = 0
        return True
    
    def stop_capture(self):
        """Stop network capture"""
        self.capturing = False
        return True
    
    def add_packet(self, packet_data):
        """Add a captured packet to the log"""
        if not self.capturing:
            return None
        
        with self._lock:
            self.packet_id += 1
            packet = {
                'id': self.packet_id,
                'timestamp': time.strftime('%H:%M:%S.%f')[:-3],
                'time_epoch': time.time(),
                'protocol': packet_data.get('protocol', 'TCP'),
                'source': packet_data.get('source', ''),
                'destination': packet_data.get('destination', ''),
                'source_port': packet_data.get('source_port', 0),
                'destination_port': packet_data.get('destination_port', 0),
                'length': packet_data.get('length', 0),
                'info': packet_data.get('info', ''),
                'payload': packet_data.get('payload', ''),
                'flags': packet_data.get('flags', []),
            }
            
            # Apply filters
            if self.filters:
                packet_str = json.dumps(packet).lower()
                if not all(f.lower() in packet_str for f in self.filters):
                    return None
            
            self.packets.append(packet)
            
            # Trim
            if len(self.packets) > self.max_packets:
                self.packets = self.packets[-self.max_packets:]
            
            return packet['id']
    
    def add_http_traffic(self, method, url, status_code, size, duration):
        """Add HTTP traffic entry"""
        parsed = urlparse(url)
        return self.add_packet({
            'protocol': 'HTTP',
            'source': 'client',
            'destination': parsed.netloc,
            'source_port': 0,
            'destination_port': 443 if parsed.scheme == 'https' else 80,
            'length': size,
            'info': f"{method} {parsed.path} -> {status_code} ({duration:.2f}s)",
            'payload': json.dumps({'method': method, 'url': url, 'status': status_code}),
            'flags': ['SYN', 'ACK'],
        })
    
    def add_dns_query(self, domain, ips=None):
        """Add DNS query entry"""
        info = f"DNS A {domain}"
        if ips:
            info += f" -> {', '.join(ips)}"
        
        return self.add_packet({
            'protocol': 'DNS',
            'source': 'client',
            'destination': 'dns-server',
            'source_port': 5353,
            'destination_port': 53,
            'length': len(domain) + 20,
            'info': info,
            'payload': json.dumps({'domain': domain, 'ips': ips or []}),
        })
    
    def add_tcp_connection(self, host, port, status='established'):
        """Add TCP connection entry"""
        flags_map = {
            'established': ['SYN', 'SYN-ACK', 'ACK'],
            'closed': ['FIN', 'ACK'],
            'timeout': ['SYN'],
            'refused': ['SYN', 'RST'],
        }
        
        return self.add_packet({
            'protocol': 'TCP',
            'source': 'client',
            'destination': host,
            'source_port': 0,
            'destination_port': port,
            'length': 60,
            'info': f"TCP {status} {host}:{port}",
            'flags': flags_map.get(status, ['SYN']),
        })
    
    def set_filters(self, filters):
        """Set active capture filters"""
        self.filters = filters
    
    def get_packets(self, limit=100, protocol=None):
        """Get captured packets"""
        with self._lock:
            packets = self.packets
            
            if protocol:
                packets = [p for p in packets if p['protocol'] == protocol.upper()]
            
            return packets[-limit:]
    
    def get_traffic_summary(self):
        """Get traffic summary statistics"""
        with self._lock:
            summary = {
                'total_packets': len(self.packets),
                'protocols': {},
                'total_bytes': sum(p.get('length', 0) for p in self.packets),
                'top_hosts': {},
            }
            
            for p in self.packets:
                proto = p.get('protocol', 'Unknown')
                summary['protocols'][proto] = summary['protocols'].get(proto, 0) + 1
                
                dest = p.get('destination', '')
                if dest:
                    summary['top_hosts'][dest] = summary['top_hosts'].get(dest, 0) + 1
            
            # Sort and trim
            summary['top_hosts'] = dict(sorted(summary['top_hosts'].items(), key=lambda x: x[1], reverse=True)[:10])
            
            return summary