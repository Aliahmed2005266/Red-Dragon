"""
Extended API endpoints for fuzzing, subdomain enumeration, site mapping, and AI agent
"""

from flask import Flask, request, jsonify, session as flask_session
import json
import threading
import time
import requests
from urllib.parse import urlparse
import os
import re

from scanner_modules.web_proxy import RequestInterceptor, NetworkCapture
from scanner_modules.encoding_handler import (
    EncodingHandler, AdvancedEncoder, Decoder,
    encode_payload, decode_payload, get_available_encodings
)

# Global AI agent instance
ai_agent_instance = None
agent_lock = threading.Lock()

def get_ai_agent():
    global ai_agent_instance
    if ai_agent_instance is None:
        from scanner_modules.ai_agent import AIAgent
        ai_agent_instance = AIAgent()
    return ai_agent_instance

def register_extensions(app):
    """Register all extension endpoints with the Flask app"""
    
    # ============ FUZZING ENDPOINTS ============
    
    @app.route('/api/fuzz', methods=['POST'])
    def fuzz_target():
        """Fuzz a target with wordlist"""
        from scanner_modules.fuzzer import Fuzzer
        
        data = request.get_json()
        target_url = data.get('target_url')
        wordlist_content = data.get('wordlist', None)
        mode = data.get('mode', 'directories')  # directories, parameters
        
        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400
        
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        fuzzer = Fuzzer(target_url, session)
        
        # Load custom wordlist if provided
        wordlist = None
        if wordlist_content:
            wordlist = fuzzer.load_wordlist(wordlist_content)
        
        results = []
        if mode == 'directories':
            results = fuzzer.fuzz_directories(wordlist)
        elif mode == 'parameters':
            param_name = data.get('param_name', 'id')
            results = fuzzer.fuzz_parameters(wordlist, param_name)
        
        return jsonify({
            'target': target_url,
            'mode': mode,
            'results': results,
            'findings': fuzzer.findings
        })
    
    @app.route('/api/fuzz/wordlist/builtin', methods=['GET'])
    def get_builtin_wordlist():
        """Get the built-in wordlist for reference"""
        from scanner_modules.fuzzer import Fuzzer
        session = requests.Session()
        fuzzer = Fuzzer('https://example.com', session)
        return jsonify({
            'directories': fuzzer.common_dirs,
            'files': fuzzer.common_files,
            'count': len(fuzzer.common_dirs) + len(fuzzer.common_files)
        })
    
    # ============ PARAMETER DISCOVERY ============

    @app.route('/api/parameters', methods=['POST'])
    def discover_parameters():
        """Discover the parameters a target accepts.

        Runs the parameter discovery module directly so the UI can request
        parameters on demand without waiting for a full vulnerability scan.
        """
        from scanner_modules.param_discovery import ParamDiscovery

        data = request.get_json(silent=True) or {}
        target_url = (data.get('target_url') or '').strip()

        if not target_url:
            return jsonify({'error': 'Target URL or IP is required'}), 400

        if not target_url.startswith(('http://', 'https://')):
            target_url = f'http://{target_url}'

        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        try:
            discovery = ParamDiscovery(target_url, session)

            # Optional tuning so the UI can trade speed for coverage
            if data.get('max_pages') is not None:
                discovery.max_pages = max(1, min(int(data['max_pages']), 50))
            if data.get('probe') is False:
                discovery.probe_limit = 0

            discovery.scan()
        except Exception as e:
            return jsonify({'error': f'Parameter discovery failed: {str(e)}'}), 500

        return jsonify({
            'target': target_url,
            'parameters': discovery.discovered_parameters,
            'count': len(discovery.discovered_parameters),
            'findings': discovery.findings,
        })

    # ============ TECHNOLOGY FINGERPRINTING ============

    @app.route('/api/technology', methods=['POST'])
    def detect_technology():
        """Report the architecture behind a target.

        Returns the server, languages, databases, CMS, frameworks, frontend
        libraries and CDN/WAF, each with a confidence level and the evidence
        that produced the detection.
        """
        from scanner_modules.tech_fingerprint import TechFingerprint

        data = request.get_json(silent=True) or {}
        target_url = (data.get('target_url') or '').strip()

        if not target_url:
            return jsonify({'error': 'Target URL or IP is required'}), 400

        if not target_url.startswith(('http://', 'https://')):
            target_url = f'http://{target_url}'

        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        try:
            fingerprint = TechFingerprint(target_url, session)
            findings = fingerprint.scan()
        except Exception as e:
            return jsonify({'error': f'Fingerprinting failed: {str(e)}'}), 500

        return jsonify({
            'target': target_url,
            'summary': fingerprint.summary(),
            'architecture': fingerprint.architecture,
            'technologies': fingerprint.technologies,
            'has_database': fingerprint.has_database_evidence(),
            'databases': fingerprint.architecture.get('databases', []),
            'evidence': fingerprint.evidence,
            'findings': findings,
        })

    # ============ SUBDOMAIN ENUMERATION ============
    
    @app.route('/api/subdomains', methods=['POST'])
    def enumerate_subdomains():
        """Enumerate subdomains for a target"""
        from scanner_modules.subdomain_enum import SubdomainEnumerator
        
        data = request.get_json()
        target_url = data.get('target_url')
        wordlist_content = data.get('wordlist', None)
        
        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400
        
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        enumerator = SubdomainEnumerator(target_url, session)
        
        # Load custom wordlist if provided
        wordlist = None
        if wordlist_content:
            wordlist = enumerator.load_wordlist(wordlist_content)
        
        results = enumerator.scan(wordlist)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_results = []
        for r in results:
            domain = r.get('subdomain', '')
            if domain not in seen:
                seen.add(domain)
                unique_results.append(r)
        
        return jsonify({
            'target': target_url,
            'domain': enumerator.domain,
            'subdomains': unique_results,
            'count': len(unique_results),
            'findings': enumerator.findings
        })
    
    @app.route('/api/subdomains/wordlist', methods=['GET'])
    def get_subdomain_wordlist():
        """Get the built-in subdomain wordlist"""
        from scanner_modules.subdomain_enum import SubdomainEnumerator
        session = requests.Session()
        enumerator = SubdomainEnumerator('https://example.com', session)
        return jsonify({
            'subdomains': enumerator.common_subdomains,
            'count': len(enumerator.common_subdomains)
        })
    
    # ============ SITE MAPPER ============
    
    @app.route('/api/map', methods=['POST'])
    def map_site():
        """Generate 2D site map"""
        from scanner_modules.site_mapper import SiteMapper
        
        data = request.get_json()
        target_url = data.get('target_url')
        max_depth = data.get('max_depth', 2)
        
        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400
        
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        mapper = SiteMapper(target_url, session)
        map_data = mapper.scan(max_depth)
        
        return jsonify({
            'target': target_url,
            'map': map_data,
            'stats': map_data.get('stats', {})
        })
    
    # ============ AI AGENT ============
    # NOTE: /api/ai/configure is defined in server.py, which is the more
    # complete version because it also selects the provider. Defining it here
    # as well made Flask abort the whole registration pass, which silently
    # dropped every endpoint below this point.

    @app.route('/api/ai/status', methods=['GET'])
    def ai_status():
        """Check AI agent configuration status"""
        agent = get_ai_agent()
        return jsonify({
            'configured': agent.api_key is not None,
            'model': agent.model if agent.api_key else None
        })
    
    # NOTE: /api/ai/configure, /api/ai/chat and /api/ai/analyze are all defined
    # in server.py. Defining them here as well made Flask abort the whole
    # registration pass, which silently dropped every endpoint below this
    # point. The server.py versions are the ones the UI uses, because they also
    # accept provider/api_key/model and configure the agent per request.

    @app.route('/api/ai/clear', methods=['POST'])
    def ai_clear():
        """Clear AI conversation history"""
        agent = get_ai_agent()
        agent.clear_history()
        return jsonify({'status': 'cleared'})
    
    @app.route('/api/ai/remediation', methods=['POST'])
    def ai_remediation():
        """Generate remediation summary"""
        data = request.get_json()
        findings = data.get('findings')
        
        if not findings:
            return jsonify({'error': 'Findings are required'}), 400
        
        agent = get_ai_agent()
        remediation = agent.generate_remediation_summary(findings)
        
        return jsonify({'remediation': remediation or 'No remediation generated'})
    
    # ============ WEB PROXY / INTERCEPTOR ============
    
    # Global proxy and network capture instances
    request_interceptor = RequestInterceptor()
    network_capture = NetworkCapture()
    
    @app.route('/api/proxy/history', methods=['GET'])
    def proxy_history():
        """Get intercepted request history"""
        limit = request.args.get('limit', 50, type=int)
        return jsonify({'history': request_interceptor.get_history(limit)})
    
    @app.route('/api/proxy/request/<int:request_id>', methods=['GET'])
    def proxy_request_detail(request_id):
        """Get full request/response details"""
        return jsonify(request_interceptor.get_request_detail(request_id))
    
    @app.route('/api/proxy/replay', methods=['POST'])
    def proxy_replay():
        """Replay a request with optional modifications"""
        data = request.get_json()
        request_id = data.get('request_id')
        modifications = data.get('modifications', {})
        
        if not request_id:
            return jsonify({'error': 'Request ID is required'}), 400
        
        result = request_interceptor.replay_request(request_id, modifications)
        return jsonify(result)
    
    @app.route('/api/proxy/modify', methods=['POST'])
    def proxy_modify():
        """Modify a captured request"""
        data = request.get_json()
        request_id = data.get('request_id')
        
        result = request_interceptor.modify_request(
            request_id,
            method=data.get('method'),
            url=data.get('url'),
            headers=data.get('headers'),
            body=data.get('body')
        )
        
        return jsonify({'success': result})
    
    @app.route('/api/proxy/toggle', methods=['POST'])
    def proxy_toggle():
        """Toggle interception on/off"""
        state = request_interceptor.toggle_intercept()
        return jsonify({'intercept_enabled': state})
    
    @app.route('/api/proxy/search', methods=['GET'])
    def proxy_search():
        """Search intercepted requests"""
        query = request.args.get('q', '')
        results = request_interceptor.search_requests(query)
        return jsonify({'results': results, 'count': len(results)})
    
    @app.route('/api/proxy/clear', methods=['POST'])
    def proxy_clear():
        """Clear interception history"""
        request_interceptor.clear_history()
        return jsonify({'status': 'cleared'})
    
    # ============ NETWORK CAPTURE (WIRESHARK-LIKE) ============
    
    @app.route('/api/network/start', methods=['POST'])
    def network_start():
        """Start network traffic capture"""
        network_capture.start_capture()
        return jsonify({'status': 'capturing'})
    
    @app.route('/api/network/stop', methods=['POST'])
    def network_stop():
        """Stop network capture"""
        network_capture.stop_capture()
        return jsonify({'status': 'stopped'})
    
    @app.route('/api/network/packets', methods=['GET'])
    def network_packets():
        """Get captured packets"""
        limit = request.args.get('limit', 100, type=int)
        protocol = request.args.get('protocol', None)
        return jsonify({
            'packets': network_capture.get_packets(limit, protocol),
            'capturing': network_capture.capturing
        })
    
    @app.route('/api/network/summary', methods=['GET'])
    def network_summary():
        """Get network traffic summary"""
        return jsonify(network_capture.get_traffic_summary())
    
    @app.route('/api/network/filter', methods=['POST'])
    def network_filter():
        """Set network capture filters"""
        data = request.get_json()
        filters = data.get('filters', [])
        network_capture.set_filters(filters)
        return jsonify({'filters': filters})
    
    @app.route('/api/network/http', methods=['POST'])
    def network_add_http():
        """Manually add HTTP traffic to the capture"""
        data = request.get_json()
        network_capture.add_http_traffic(
            data['method'], data['url'],
            data.get('status_code', 0),
            data.get('size', 0),
            data.get('duration', 0)
        )
        return jsonify({'status': 'added'})
    
    # ============ INTRUDER (AUTOMATED PAYLOAD ATTACKS) ============

    # Global registry of running/completed intruder attacks
    intruder_attacks = {}

    @app.route('/api/intruder/start', methods=['POST'])
    def intruder_start():
        """Start an automated Intruder attack"""
        from scanner_modules.intruder import Intruder

        data = request.get_json()
        target_url = data.get('target_url')
        payloads = data.get('payloads', [])
        parameters = data.get('parameters', [])
        attack_type = data.get('attack_type', 'sniper')
        match_type = data.get('match_type', 'contains')
        match_value = data.get('match_value', '')
        method = data.get('method', 'GET')
        headers = data.get('headers', {})
        body = data.get('body')
        max_threads = data.get('max_threads', 20)

        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400
        if not payloads or not any(payloads):
            return jsonify({'error': 'At least one payload is required'}), 400
        if not parameters:
            return jsonify({'error': 'At least one parameter is required'}), 400

        # Normalize payloads: list of lists (one list per payload set)
        payload_sets = []
        for pset in payloads:
            if isinstance(pset, str):
                pset = [p for p in pset.split('\n') if p.strip()]
            payload_sets.append([str(p) for p in pset if str(p).strip()])
        if not payload_sets or not payload_sets[0]:
            return jsonify({'error': 'At least one payload is required'}), 400

        # Normalize parameters: list of dicts {name, position}
        normalized_params = []
        for param in parameters:
            if isinstance(param, str):
                normalized_params.append({'name': param.strip(), 'position': 'query'})
            else:
                normalized_params.append({
                    'name': str(param.get('name', '')).strip(),
                    'position': param.get('position', 'query'),
                })
        normalized_params = [p for p in normalized_params if p['name']]

        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        intruder = Intruder(
            target_url, session,
            payloads=payload_sets,
            parameters=normalized_params,
            attack_type=attack_type,
            match_type=match_type,
            match_value=match_value,
            method=method,
            headers=headers,
            body=body,
            max_threads=max_threads,
        )
        intruder_attacks[intruder.attack_id] = intruder
        intruder.start_async()

        return jsonify({
            'attack_id': intruder.attack_id,
            'status': 'started',
            'attack_type': attack_type,
            'target': target_url,
        })

    @app.route('/api/intruder/status/<attack_id>', methods=['GET'])
    def intruder_status(attack_id):
        """Get the status and results of an Intruder attack"""
        intruder = intruder_attacks.get(attack_id)
        if not intruder:
            return jsonify({'error': 'Attack not found'}), 404
        return jsonify(intruder.get_status())

    @app.route('/api/intruder/stop/<attack_id>', methods=['POST'])
    def intruder_stop(attack_id):
        """Stop a running Intruder attack"""
        intruder = intruder_attacks.get(attack_id)
        if not intruder:
            return jsonify({'error': 'Attack not found'}), 404
        intruder.stop()
        return jsonify({'status': 'stopping', 'attack_id': attack_id})

    @app.route('/api/intruder/attacks', methods=['GET'])
    def intruder_list():
        """List all intruder attacks with basic status"""
        return jsonify({
            'attacks': [
                {'attack_id': aid, **{k: v for k, v in intr.get_status().items()
                 if k in ('attack_type', 'target', 'is_running', 'completed', 'matched', 'total_requests')}}
                for aid, intr in intruder_attacks.items()
            ]
        })

    @app.route('/api/intruder/presets', methods=['GET'])
    def intruder_presets():
        """Return built-in payload lists for brute forcing (Burp-style presets)"""
        from scanner_modules.intruder import Intruder
        presets = getattr(Intruder, 'PAYLOAD_PRESETS', {})
        return jsonify({
            name: {
                'label': meta.get('label', name),
                'items': meta.get('items', []),
                'count': len(meta.get('items', [])),
            }
            for name, meta in presets.items()
        })

    @app.route('/api/intruder/bruteforce', methods=['POST'])
    def intruder_bruteforce():
        """Start a Burp Suite style credential brute force attack.

        Uses the Intruder engine with two payload sets (usernames + passwords)
        combined via Cluster Bomb (cross-product) or Pitchfork (parallel).
        Valid logins are detected with failure/success indicator strings.
        """
        from scanner_modules.intruder import Intruder

        data = request.get_json()
        target_url = data.get('target_url')
        method = data.get('method', 'POST').upper()
        username_param = data.get('username_param', 'username')
        password_param = data.get('password_param', 'password')
        position = data.get('position', 'body')
        attack_mode = data.get('attack_mode', 'cluster_bomb')
        failure_indicator = data.get('failure_indicator', '')
        success_indicator = data.get('success_indicator', '')
        headers = data.get('headers', {})
        body = data.get('body') or None

        def _split_lines(value):
            if isinstance(value, str):
                return [v.strip() for v in value.split('\n') if v.strip()]
            return [str(v).strip() for v in (value or []) if str(v).strip()]

        users = _split_lines(data.get('users', ''))
        passwords = _split_lines(data.get('passwords', ''))

        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400
        if not users:
            return jsonify({'error': 'Username list is required'}), 400
        if not passwords:
            return jsonify({'error': 'Password list is required'}), 400

        # Burp-style success detection:
        #   - failure indicator set -> valid login = response NOT containing it
        #   - success indicator set (takes precedence) -> valid login = response containing it
        if success_indicator:
            match_type, match_value = 'contains', success_indicator
        elif failure_indicator:
            match_type, match_value = 'not_contains', failure_indicator
        else:
            match_type, match_value = 'none', ''

        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        intruder = Intruder(
            target_url, session,
            payloads=[users, passwords],
            parameters=[
                {'name': username_param, 'position': position},
                {'name': password_param, 'position': position},
            ],
            attack_type=attack_mode if attack_mode in ('cluster_bomb', 'pitchfork') else 'cluster_bomb',
            match_type=match_type,
            match_value=match_value,
            method=method,
            headers=headers,
            body=body,
        )
        intruder_attacks[intruder.attack_id] = intruder
        intruder.start_async()

        total = (len(users) * len(passwords)) if intruder.attack_type == 'cluster_bomb' \
            else min(len(users), len(passwords))

        return jsonify({
            'attack_id': intruder.attack_id,
            'status': 'started',
            'attack_mode': intruder.attack_type,
            'match_mode': match_type,
            'total_requests': total,
            'usernames': len(users),
            'passwords': len(passwords),
        })

    # ============ REPEATER (MANUAL REQUEST REPLAY) ============

    @app.route('/api/repeater/send', methods=['POST'])
    def repeater_send():
        """Send a manually crafted HTTP request (Repeater functionality)"""
        data = request.get_json()
        method = data.get('method', 'GET').upper()
        url = data.get('url')
        headers = data.get('headers', {})
        body = data.get('body')

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        session = requests.Session()
        req_headers = dict(headers)

        start = time.time()
        try:
            resp = session.request(
                method, url,
                headers=req_headers,
                data=body if body else None,
                timeout=30,
                allow_redirects=False,
                verify=False,
            )
            elapsed = time.time() - start

            return jsonify({
                'method': method,
                'url': url,
                'status_code': resp.status_code,
                'reason': resp.reason,
                'response_headers': dict(resp.headers),
                'response_body': resp.text[:100000],
                'response_length': len(resp.text),
                'elapsed': round(elapsed, 3),
            })
        except requests.exceptions.Timeout:
            return jsonify({'error': f'Request to {url} timed out after 30s'}), 504
        except requests.exceptions.ConnectionError as e:
            return jsonify({'error': f'Connection failed: {str(e)}'}), 502
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # ============ SOURCE ANALYZER (FETCH & ANALYZE WEBSITE SOURCE) ============

    def analyze_website_source(html, response_headers, final_url):
        """Analyze fetched HTML/source for technologies and security issues."""
        issues = []
        technologies = set()

        def add(severity, title, description, count=None):
            item = {'severity': severity, 'title': title, 'description': description}
            if count is not None:
                item['count'] = count
            issues.append(item)

        # ---- Technology fingerprinting ----
        tech_patterns = {
            'WordPress': [r'wp-content', r'wp-includes', r'wp-json'],
            'Drupal': [r'/sites/default/files', r'drupal'],
            'Joomla': [r'/media/jui/', r'joomla'],
            'React': [r'__NEXT_DATA__', r'data-reactroot', r'react(?:\.production)?(?:\.min)?\.js'],
            'Next.js': [r'/_next/static/'],
            'Vue.js': [r'data-v-app', r'vue(?:\.runtime)?(?:\.min)?\.js'],
            'Angular': [r'ng-version', r'angular(?:\.min)?\.js'],
            'jQuery': [r'jquery[.-]'],
            'Bootstrap': [r'bootstrap(?:\.min)?\.(?:js|css)'],
            'Google Analytics': [r'google-analytics\.com', r'gtag/js'],
            'Cloudflare': [r'cdn-cgi/', r'cloudflare'],
            'PHP': [r'\.php["\']'],
            'ASP.NET': [r'__VIEWSTATE', r'aspnet'],
            'Font Awesome': [r'font-awesome', r'fontawesome'],
            'Google Fonts': [r'fonts\.googleapis\.com'],
        }
        for tech, pats in tech_patterns.items():
            if any(re.search(p, html, re.I) for p in pats):
                technologies.add(tech)
        gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I)
        if gen:
            technologies.add(gen.group(1).strip())

        # ---- Hard-coded secrets in source ----
        secret_patterns = [
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'ghp_[A-Za-z0-9]{36}', 'GitHub Token'),
            (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
            (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Secret Key'),
            (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'JWT Token'),
            (r'(?i)(api[_-]?key|secret|passwd|password)\s*[:=]\s*["\'][^"\']{8,}["\']', 'Hard-coded credential variable'),
        ]
        for pat, label in secret_patterns:
            matches = re.findall(pat, html)
            if matches:
                add('Critical', f'{label} exposed in source',
                    f'Found {len(matches)} occurrence(s) of {label} in the page source. Remove secrets from client-side code.',
                    len(matches))

        # ---- Sensitive HTML comments ----
        comments = re.findall(r'<!--(.*?)-->', html, re.S)
        interesting = [c.strip() for c in comments if re.search(
            r'(?i)(todo|fixme|hack|password|secret|debug|test user|admin|api key|config|backup|\.env)', c)]
        if interesting:
            add('Medium', 'Sensitive information in HTML comments',
                f'{len(interesting)} comment(s) may reveal internal details to attackers.',
                len(interesting))

        # ---- Mixed content on HTTPS pages ----
        if final_url.startswith('https'):
            insecure = re.findall(r'(?:src|href|action)=["\']http://[^"\']+', html, re.I)
            if insecure:
                add('Medium', 'Mixed content (HTTP resources on HTTPS page)',
                    f'{len(insecure)} resource(s) loaded over plain HTTP — can be intercepted or blocked by browsers.',
                    len(insecure))

        # ---- Password fields ----
        pw_fields = re.findall(r'<input[^>]*type=["\']password["\'][^>]*>', html, re.I)
        if pw_fields:
            if not re.search(r'(?i)autocomplete=["\'](?:off|new-password)', ' '.join(pw_fields)):
                add('Low', 'Password field without autocomplete policy',
                    'Browsers may store credentials in plain text.')
            if not final_url.startswith('https'):
                add('Critical', 'Password field served over plain HTTP',
                    'Credentials can be intercepted in transit.')

        # ---- Inline JS surface ----
        inline_handlers = len(re.findall(r'\son[a-z]+\s*=\s*["\']', html, re.I))
        if inline_handlers:
            add('Info', 'Inline JavaScript event handlers',
                f'{inline_handlers} inline handler(s) increase XSS surface and conflict with strict CSP.',
                inline_handlers)
        inline_scripts = len(re.findall(r'<script(?![^>]*\bsrc=)[^>]*>', html, re.I))
        if inline_scripts:
            add('Info', 'Inline <script> blocks',
                f'{inline_scripts} inline script block(s) found in the source.', inline_scripts)

        # ---- Iframes ----
        iframes = len(re.findall(r'<iframe\b', html, re.I))
        if iframes:
            add('Low', 'Embedded iframes',
                f'{iframes} iframe(s) may load third-party content (clickjacking surface).', iframes)

        # ---- Forms ----
        forms = re.findall(r'<form[^>]*>', html, re.I)
        ext_forms = [f for f in forms if re.search(r'action=["\']http', f, re.I)]
        if ext_forms:
            add('Medium', 'Forms submitting to external hosts',
                f'{len(ext_forms)} form(s) post data to a different origin.', len(ext_forms))

        # ---- Email disclosure ----
        emails = list(dict.fromkeys(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html)))[:20]
        if emails:
            add('Info', 'Email addresses disclosed',
                f'{len(emails)} email(s) visible in source (spam / OSINT target).', len(emails))

        # ---- Version disclosure ----
        ver_comments = re.findall(r'(?i)<!--[^>]*?(?:version|v\s*[:=]?)\s*\d+(?:\.\d+)+[^>]*?-->', html)
        if ver_comments or gen:
            add('Low', 'Version disclosure',
                'Version information revealed in meta generator tag or comments helps attackers find known CVEs.')

        # ---- Missing security headers (from live response) ----
        hdrs = {k.lower(): v for k, v in (response_headers or {}).items()}
        required_headers = [
            ('content-security-policy', 'Content-Security-Policy'),
            ('x-frame-options', 'X-Frame-Options'),
            ('strict-transport-security', 'Strict-Transport-Security'),
            ('x-content-type-options', 'X-Content-Type-Options'),
            ('referrer-policy', 'Referrer-Policy'),
        ]
        for hkey, hname in required_headers:
            if hkey not in hdrs:
                sev = 'High' if hkey in ('content-security-policy', 'strict-transport-security') else 'Low'
                add(sev, f'Missing security header: {hname}',
                    f'The server does not send the {hname} header.')

        # ---- Extract resources ----
        links = list(dict.fromkeys(re.findall(r'<a[^>]+href=["\']([^"\'#]+)', html, re.I)))[:100]
        scripts = list(dict.fromkeys(re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.I)))[:50]
        styles = list(dict.fromkeys(re.findall(r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)', html, re.I)))[:50]
        form_details = [{'tag': f[:200]} for f in forms[:20]]

        return {
            'issues': issues,
            'technologies': sorted(technologies),
            'links': links,
            'scripts': scripts,
            'styles': styles,
            'forms': form_details,
            'emails': emails,
            'comments_sample': [c.strip()[:300] for c in comments[:30]],
        }

    @app.route('/api/source/fetch', methods=['POST'])
    def source_fetch():
        """Fetch a website and return its source code with a security analysis"""
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        try:
            resp = requests.get(
                url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
                },
                timeout=30, verify=False, allow_redirects=True,
            )
        except requests.exceptions.Timeout:
            return jsonify({'error': f'Request to {url} timed out after 30s'}), 504
        except requests.exceptions.ConnectionError as e:
            return jsonify({'error': f'Connection failed: {str(e)}'}), 502
        except Exception as e:
            return jsonify({'error': str(e)}), 500

        source = resp.text or ''
        analysis = analyze_website_source(source, resp.headers, resp.url)
        source_lines = source.count('\n') + 1 if source else 0

        return jsonify({
            'url': url,
            'final_url': resp.url,
            'status_code': resp.status_code,
            'reason': resp.reason,
            'response_headers': dict(resp.headers),
            'source': source[:200000],
            'truncated': len(source) > 200000,
            'total_size': len(source),
            'total_lines': source_lines,
            'elapsed': round(resp.elapsed.total_seconds(), 3) if resp.elapsed else None,
            'analysis': analysis,
        })

    # ============ COMBINED SCAN WITH ALL FEATURES ============
    
    @app.route('/api/scan/deep', methods=['POST'])
    def deep_scan():
        """Perform deep scan including fuzzing, subdomain enum, and site mapping"""
        from scanner_modules.fuzzer import Fuzzer
        from scanner_modules.subdomain_enum import SubdomainEnumerator
        from scanner_modules.site_mapper import SiteMapper
        
        data = request.get_json()
        target_url = data.get('target_url')
        
        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400
        
        scan_id = f"deep_{int(__import__('time').time())}"
        
        def run_deep_scan():
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            results = {
                'target': target_url,
                'fuzzing': [],
                'subdomains': [],
                'site_map': None,
                'findings': []
            }
            
            # Fuzzing
            try:
                fuzzer = Fuzzer(target_url, session)
                fuzzer.fuzz_directories()
                results['fuzzing'] = fuzzer.results
                results['findings'].extend(fuzzer.findings)
            except Exception as e:
                print(f"Fuzzing error: {e}")
            
            # Subdomain enumeration
            try:
                enumerator = SubdomainEnumerator(target_url, session)
                enumerator.scan()
                results['subdomains'] = enumerator.subdomains
                results['findings'].extend(enumerator.findings)
            except Exception as e:
                print(f"Subdomain error: {e}")
            
            # Site mapping
            try:
                mapper = SiteMapper(target_url, session)
                results['site_map'] = mapper.scan()
            except Exception as e:
                print(f"Site mapping error: {e}")
            
            # Store results
            from server import scan_results
            scan_results[scan_id] = results
            
            from server import active_scans
            if scan_id in active_scans:
                active_scans[scan_id]['status'] = 'completed'
        
        from server import active_scans
        active_scans[scan_id] = {
            'target': target_url,
            'status': 'running',
            'started_at': __import__('datetime').datetime.now().isoformat()
        }
        
        thread = threading.Thread(target=run_deep_scan)
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'target': target_url
        })
    
    # ============ FUZZ-DRIVEN VULNERABILITY TESTING (ASYNC) ============

    # Global registry of running/completed fuzz attack jobs
    fuzz_jobs = {}

    @app.route('/api/fuzz/attack', methods=['POST'])
    def fuzz_attack_start():
        """Start an async fuzz-then-vuln-test attack on a target"""
        from scanner_modules.fuzzer import Fuzzer

        data = request.get_json()
        target_url = data.get('target_url')
        wordlist_content = data.get('wordlist', None)
        vuln_tests = data.get('vuln_tests', ['sqli', 'xss', 'lfi', 'redirect'])
        max_endpoints = min(int(data.get('max_endpoints', 12)), 30)

        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        import uuid
        job_id = str(uuid.uuid4())
        fuzz_jobs[job_id] = {
            'target': target_url,
            'status': 'running',
            'phase': 'Starting...',
            'progress': 0,
            'started_at': __import__('datetime').datetime.now().isoformat(),
            'completed_at': None,
            'discovered': [],
            'endpoints_tested': [],
            'vuln_findings': [],
            'fuzz_findings': [],
            'error': None,
        }

        def run_job():
            job = fuzz_jobs[job_id]
            try:
                session = requests.Session()
                session.headers.update({
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                fuzzer = Fuzzer(target_url, session)

                wordlist = None
                if wordlist_content:
                    wordlist = fuzzer.load_wordlist(wordlist_content)

                def progress_cb(phase, pct):
                    job['phase'] = phase
                    job['progress'] = pct

                summary = fuzzer.fuzz_and_test(
                    wordlist=wordlist,
                    vuln_tests=vuln_tests,
                    max_endpoints=max_endpoints,
                    progress_callback=progress_cb,
                )

                job['discovered'] = fuzzer.results
                job['fuzz_findings'] = fuzzer.findings
                job['endpoints_tested'] = summary['endpoints_tested']
                job['vuln_findings'] = summary['vuln_findings']
                job['endpoints_discovered'] = summary['endpoints_discovered']
                job['status'] = 'completed'
            except Exception as e:
                job['status'] = 'failed'
                job['error'] = str(e)
            finally:
                job['completed_at'] = __import__('datetime').datetime.now().isoformat()

        threading.Thread(target=run_job, daemon=True).start()

        return jsonify({
            'job_id': job_id,
            'status': 'started',
            'target': target_url,
        })

    @app.route('/api/fuzz/attack/<job_id>', methods=['GET'])
    def fuzz_attack_status(job_id):
        """Get the status/results of a fuzz attack job"""
        job = fuzz_jobs.get(job_id)
        if not job:
            return jsonify({'error': 'Job not found'}), 404
        return jsonify(job)

    @app.route('/api/fuzz/attack/jobs', methods=['GET'])
    def fuzz_attack_list():
        """List all fuzz attack jobs"""
        return jsonify({
            'jobs': [
                {'job_id': jid, **{k: v for k, v in job.items()
                 if k in ('target', 'status', 'phase', 'progress', 'started_at')}}
                for jid, job in fuzz_jobs.items()
            ]
        })


    # ============ ENCODER / DECODER ============

    @app.route('/api/encode', methods=['POST'])
    def encode_payload():
        """Encode a payload using the specified encoding type"""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        payload = data.get('payload', '')
        encoding_type = data.get('encoding_type', 'url')
        if not payload:
            return jsonify({'error': 'No payload provided'}), 400
        try:
            result = encode_payload(payload, encoding_type)
            return jsonify({'encoded': result, 'encoding_type': encoding_type})
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': f'Encoding failed: {str(e)}'}), 500

    @app.route('/api/decode', methods=['POST'])
    def decode_payload():
        """Decode a payload using the specified decoding type"""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        payload = data.get('payload', '')
        decoding_type = data.get('decoding_type', 'url')
        if not payload:
            return jsonify({'error': 'No payload provided'}), 400
        try:
            result = decode_payload(payload, decoding_type)
            return jsonify({'decoded': result, 'decoding_type': decoding_type})
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': f'Decoding failed: {str(e)}'}), 500

    @app.route('/api/decode/all', methods=['POST'])
    def decode_all():
        """Apply all decodings to a payload"""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        payload = data.get('payload', '')
        if not payload:
            return jsonify({'error': 'No payload provided'}), 400
        results = EncodingHandler.decode_all(payload)
        return jsonify({'results': results})

    @app.route('/api/detect', methods=['POST'])
    def detect_encoding():
        """Auto-detect encoding type and decode"""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        payload = data.get('payload', '')
        if not payload:
            return jsonify({'error': 'No payload provided'}), 400
        detected, decoded = EncodingHandler.detect_and_decode(payload)
        return jsonify({'detected_encoding': detected, 'decoded': decoded})

    @app.route('/api/encodings', methods=['GET'])
    def list_encodings():
        """List all available encoding and decoding types"""
        return jsonify(get_available_encodings())

    @app.route('/api/decode/smart', methods=['POST'])
    def smart_decode():
        """Iteratively decode until no more changes detected"""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        payload = data.get('payload', '')
        if not payload:
            return jsonify({'error': 'No payload provided'}), 400
        result = Decoder.smart_decode(payload)
        return jsonify({'original': payload, 'decoded': result})

    @app.route('/api/decode/brute', methods=['POST'])
    def brute_decode():
        """Try all decoding methods and return all successful results"""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        payload = data.get('payload', '')
        if not payload:
            return jsonify({'error': 'No payload provided'}), 400
        results = Decoder.brute_force_decode(payload)
        return jsonify({'original': payload, 'results': results})

    # ============ APPLICATION / SETTINGS ENDPOINTS ============
    # Consumed by the installed desktop app for first-run setup and the
    # about screen. Registered here so they travel with the other extensions.

    @app.route('/api/app/info', methods=['GET'])
    def app_info():
        """Runtime facts the shell needs to render the about screen.

        Never returns the launch token: the UI already has it, and echoing it
        back would put it in every devtools network log.
        """
        from config_store import get_store
        import platform
        import sys as _sys

        settings = get_store()
        return jsonify({
            'name': 'Red Dragon',
            'version': app.config.get('RED_DRAGON_VERSION', '1.0.0'),
            'author': 'aegis cyber works',
            'python': _sys.version.split()[0],
            'platform': platform.system(),
            'machine': platform.machine(),
            'desktop': True,
            'authorized': bool(settings.get('authorized')),
            'default_target': settings.get('default_target', ''),
            'last_scan_target': settings.get('last_scan_target', ''),
            'ai_provider': settings.get('ai_provider', ''),
            'ai_model': settings.get('ai_model', ''),
        })

    @app.route('/api/app/settings', methods=['GET'])
    def get_settings():
        """Read the persisted user settings.

        API keys are intentionally not part of this: they are never persisted
        by the backend, so a leaked settings file cannot expose a credential.
        """
        from config_store import get_store
        return jsonify({'settings': get_store()})

    @app.route('/api/app/settings', methods=['POST'])
    def update_settings():
        """Merge a partial settings update and persist it."""
        from config_store import get_store, save_store

        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({'error': 'Expected a JSON object'}), 400

        # Anything outside the known schema is dropped rather than written, so
        # a crafted request cannot stuff arbitrary keys into the settings file.
        current = get_store()
        for key in current:
            if key in data:
                current[key] = data[key]

        if current.get('authorized') and not current.get('authorized_at'):
            from datetime import datetime
            current['authorized_at'] = datetime.now().isoformat()

        ok, detail = save_store(current)
        if not ok:
            return jsonify({'error': 'Could not save settings', 'detail': detail}), 500
        return jsonify({'settings': get_store()})

    @app.route('/api/app/remember-target', methods=['POST'])
    def remember_scan_target():
        """Add a target to the recents list after a scan."""
        from config_store import remember_target
        data = request.get_json(silent=True) or {}
        target = data.get('target_url') or data.get('target') or ''
        return jsonify({'settings': remember_target(target)})

    print("Extension endpoints registered: /api/fuzz, /api/subdomains, /api/map, /api/ai/*, /api/scan/deep, /api/encode, /api/decode, /api/decode/*, /api/app/*")
    return app