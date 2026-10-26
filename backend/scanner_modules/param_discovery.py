"""
Parameter Discovery Module

Finds parameters accepted by a web application and classifies what they do.

Sources of parameters:
  * the target URL query string
  * links discovered while crawling the target
  * HTML form fields (GET and POST)
  * inline JavaScript and external script files
  * REST-style path segments (/user/123)
  * a built-in wordlist, confirmed by differential response analysis

Differential probing compares the response for the target as-is against the
response with a candidate parameter set to a unique canary value. When the
status code or body size changes, the application is very likely processing
that parameter.
"""

import re
import time
from urllib.parse import urlparse, urljoin, parse_qsl, urlsplit, urlencode

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover - bs4 is a hard requirement
    BeautifulSoup = None


class ParamDiscovery:
    """Discover and classify parameters across a target application."""

    # A canary value that is effectively impossible to occur naturally, so a
    # change in the response points at the parameter being processed.
    CANARY = 'rdp7x9q2k4m8'

    # Names unlikely to be real parameters; these generate a lot of noise.
    # Note: 'id' is deliberately absent - it is one of the most common
    # parameters in web applications, despite also being an HTML attribute.
    JS_NOISE = {
        'function', 'return', 'var', 'let', 'const', 'if', 'else', 'for',
        'while', 'this', 'new', 'typeof', 'window', 'document', 'true',
        'false', 'null', 'undefined', 'prototype', 'length', 'href', 'src',
        'class', 'style', 'html', 'body', 'head',
        'string', 'number', 'boolean', 'object', 'array', 'console', 'log',
    }

    # Keyword -> parameter category. First match wins, so order matters.
    CATEGORIES = [
        ('auth', (
            'token', 'api_key', 'apikey', 'access_key', 'secret', 'password',
            'passwd', 'pwd', 'auth', 'session', 'jwt', 'credential', 'sig',
            'signature', 'hash', 'salt', 'nonce', 'csrf', 'xsrf',
        )),
        ('file', (
            'file', 'filename', 'path', 'doc', 'document', 'download',
            'upload', 'include', 'template', 'dir', 'folder', 'log',
            'image', 'img', 'attachment',
        )),
        ('redirect', (
            'redirect', 'url', 'uri', 'next', 'return', 'returnurl',
            'return_url', 'returl', 'dest', 'destination', 'goto', 'go',
            'continue', 'target', 'callback', 'rurl', 'out', 'link', 'view',
        )),
        ('pagination', (
            'page', 'pagenumber', 'offset', 'limit', 'start', 'per_page',
            'page_size', 'pagesize', 'rows', 'skip', 'cursor', 'batch',
        )),
        ('search', (
            'q', 'query', 'search', 's', 'keyword', 'keywords', 'term',
            'text', 'find', 'filter_by', 'lookup',
        )),
        ('sort', (
            'sort', 'sortby', 'sort_by', 'order', 'orderby', 'order_by',
            'direction', 'dir', 'group', 'groupby',
        )),
        ('id', (
            'id', 'uid', 'userid', 'user_id', 'pid', 'post_id', 'item_id',
            'product_id', 'order_id', 'pk', 'no', 'num', 'number',
            'index', 'idx', 'ref', 'code', 'slug',
        )),
        ('category', (
            'type', 'category', 'cat', 'tag', 'tags', 'label', 'status',
            'state', 'mode', 'format', 'action', 'do', 'op', 'func', 'method',
            'view', 'section', 'module', 'lang', 'locale', 'theme', 'version',
        )),
        ('debug', (
            'debug', 'test', 'verbose', 'admin', 'dev', 'trace', 'dump',
        )),
    ]

    # Wordlist probed against the target when nothing else is known.
    COMMON_PARAMS = [
        'id', 'q', 'query', 'search', 'page', 'limit', 'offset', 'sort',
        'order', 'filter', 'type', 'category', 'cat', 'tag', 'format',
        'callback', 'redirect', 'url', 'next', 'return', 'file', 'path',
        'name', 'user', 'username', 'email', 'password', 'token', 'key',
        'api_key', 'action', 'do', 'op', 'cmd', 'mode', 'view', 'lang',
        'include', 'template', 'download', 'upload', 'debug', 'test',
        'verbose', 'start', 'end', 'from', 'to', 'date', 'status', 'ref',
    ]

    # Regexes for parameter names inside JavaScript source
    JS_PATTERNS = [
        # ?name=value / &name=value inside a string
        re.compile(r'''[?&]([A-Za-z_][A-Za-z0-9_\-\.\[\]]{0,63})\s*=[^&"'\s]*'''),
        # data: { name: ... } / params: { name: ... }
        re.compile(r'''["']([A-Za-z_][A-Za-z0-9_\-]{0,63})["']\s*:\s*['"$\[\{]'''),
        # formData.append("name", ...)
        re.compile(r'''\.append\(\s*["']([A-Za-z_][A-Za-z0-9_\-]{0,63})["']'''),
        # searchParams.set("name", ...)
        re.compile(r'''\.set\(\s*["']([A-Za-z_][A-Za-z0-9_\-]{0,63})["']'''),
    ]

    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        parsed = urlparse(self.base_url)
        self.domain = parsed.netloc
        if ':' in self.domain:
            self.domain = self.domain.split(':')[0]
        self.session = session
        self.findings = []

        # name -> aggregated record of everything learned about the parameter
        self.parameters = {}
        # Records in list form, for the scan runner and API responses
        self.discovered_parameters = []

        # Tunables, kept modest so a scan stays quick and low-noise
        self.max_pages = 8
        self.max_scripts = 5
        self.probe_limit = 25
        self.timeout = 10

        # Internal crawl state
        self._seen_pages = set()
        self._script_urls = []

    # ------------------------------------------------------------------
    # Recording helpers
    # ------------------------------------------------------------------

    def _classify(self, name):
        """Map a parameter name to a category, or 'unknown'."""
        lowered = name.lower()
        for category, keywords in self.CATEGORIES:
            for keyword in keywords:
                if lowered == keyword or lowered.startswith(keyword + '_') \
                        or lowered.endswith('_' + keyword):
                    return category
        return 'unknown'

    def _is_valid_name(self, name):
        """Reject empty, over-long or obviously non-parameter names."""
        if not name or not isinstance(name, str) or len(name) > 64:
            return False
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_\-\.\[\]]*$', name):
            return False
        if name.lower() in self.JS_NOISE:
            return False
        if any(ord(c) < 32 for c in name):
            return False
        return True

    def record(self, name, location='query', value=None, url=None,
               method='GET', source='unknown'):
        """Store a discovered parameter, merging repeated sightings."""
        if not self._is_valid_name(name):
            return None

        if name not in self.parameters:
            self.parameters[name] = {
                'name': name,
                'type': self._classify(name),
                'locations': [],
                'methods': [],
                'sources': [],
                'values': [],
                'urls': [],
                'live': False,
                'live_confidence': 'not-probed',
            }
        entry = self.parameters[name]

        for key, val in (('locations', location), ('methods', method),
                         ('sources', source)):
            if val and val not in entry[key]:
                entry[key].append(val)

        if value not in (None, '') and str(value)[:120] not in entry['values']:
            entry['values'].append(str(value)[:120])

        target = url or self.base_url
        if target not in entry['urls'] and len(entry['urls']) < 5:
            entry['urls'].append(target)

        return entry

    def _flush(self):
        """Refresh the list-form view of self.parameters."""
        self.discovered_parameters = list(self.parameters.values())
        return self.discovered_parameters

    # ------------------------------------------------------------------
    # Extraction: URL, path segments
    # ------------------------------------------------------------------

    def extract_from_url(self, url, source='url'):
        """Record every query parameter present in a URL."""
        try:
            pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        except Exception:
            return []
        found = []
        for name, value in pairs:
            entry = self.record(name, 'query', value, url, 'GET', source)
            if entry:
                found.append(entry)
        return found

    def extract_path_params(self, url):
        """Detect REST-style path parameters such as /user/123."""
        found = []
        try:
            path = urlparse(url).path
        except Exception:
            return found

        for segment in path.split('/'):
            if not segment:
                continue
            # Trailing numeric id: /user-123
            trailing = re.search(
                r'([A-Za-z_][A-Za-z0-9_\-]{1,20})[._-](\d{1,10})$', segment
            )
            if trailing:
                found.append(self.record(
                    trailing.group(1), 'path', trailing.group(2), url, 'GET', 'path'
                ))
            elif re.fullmatch(r'\d{1,10}', segment):
                # Numeric-only segment: /123
                found.append(self.record(
                    'id', 'path', segment, url, 'GET', 'path'
                ))
            elif re.fullmatch(
                r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', segment
            ):
                # UUID segment
                found.append(self.record(
                    'uuid', 'path', segment, url, 'GET', 'path'
                ))
        return [f for f in found if f]

    # ------------------------------------------------------------------
    # Extraction: HTML, links, forms, JavaScript
    # ------------------------------------------------------------------

    def extract_from_html(self, html, page_url):
        """Pull parameters out of links, forms and scripts in a page."""
        if not html:
            return

        # Links and form actions carrying a query string
        for match in re.finditer(
            r'''(?:href|action|src|data-[\w-]*url)\s*=\s*["']([^"']+)["']''',
            html, re.I
        ):
            raw = match.group(1)
            if raw.startswith(('#', 'javascript:', 'mailto:', 'data:')):
                continue
            try:
                absolute = urljoin(page_url, raw)
            except Exception:
                continue
            if not self._same_domain(absolute):
                continue
            if '?' in absolute:
                self.extract_from_url(absolute, source='link')

        # Remember script sources so their contents can be searched too
        for match in re.finditer(
            r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', html, re.I
        ):
            try:
                src = urljoin(page_url, match.group(1))
            except Exception:
                continue
            if self._same_domain(src) and src not in self._script_urls:
                self._script_urls.append(src)

        if BeautifulSoup is None:
            return

        try:
            soup = BeautifulSoup(html, 'html.parser')
        except Exception:
            return

        # Form fields are parameters even without a query string
        for form in soup.find_all('form'):
            try:
                action = urljoin(page_url, form.get('action') or page_url)
            except Exception:
                action = page_url
            method = (form.get('method') or 'GET').upper()
            location = 'query' if method == 'GET' else 'body'
            for field in form.find_all(['input', 'textarea', 'select']):
                name = field.get('name')
                if not name:
                    continue
                if (field.get('type') or 'text').lower() in (
                    'submit', 'button', 'image', 'reset'
                ):
                    # Submit buttons are noisy and rarely interesting
                    continue
                self.record(name, location, field.get('value'), action,
                            method, 'form')

        # Inline scripts often build API request strings
        for script in soup.find_all('script'):
            if script.string:
                self.extract_from_js(script.string, source='inline-js')

    def extract_from_js(self, js, source='js'):
        """Find parameter names in JavaScript source."""
        if not js:
            return
        # Cap the amount of JS inspected to keep the scan fast
        snippet = js[:200000]
        for pattern in self.JS_PATTERNS:
            try:
                for match in pattern.finditer(snippet):
                    self.record(
                        match.group(1), 'query', None, None, 'GET', source
                    )
            except Exception:
                continue

    # ------------------------------------------------------------------
    # Crawling and probing
    # ------------------------------------------------------------------

    def _get(self, url, **kwargs):
        """GET helper that never raises."""
        try:
            return self.session.get(url, timeout=self.timeout, **kwargs)
        except Exception:
            return None

    def _same_domain(self, url):
        """Only follow links that stay on the target host."""
        try:
            host = urlparse(url).netloc.split(':')[0]
        except Exception:
            return False
        return host == self.domain or host.endswith('.' + self.domain)

    def _baseline(self):
        """Capture a baseline response used for differential comparison."""
        response = self._get(self.base_url)
        if response is None:
            return None
        return {
            'status': response.status_code,
            'length': len(response.text or ''),
        }

    def crawl(self, max_pages=None):
        """Walk same-domain pages, collecting parameters along the way."""
        max_pages = max_pages or self.max_pages
        queue = [self.base_url]
        visited = 0

        while queue and visited < max_pages:
            url = queue.pop(0)
            if url in self._seen_pages or not self._same_domain(url):
                continue
            self._seen_pages.add(url)

            response = self._get(url)
            if response is None or response.status_code >= 400:
                continue

            visited += 1
            try:
                html = response.text
            except Exception:
                continue

            self.extract_path_params(url)
            self.extract_from_html(html, url)

            # Queue same-domain links that carry a query string, so their
            # parameters get discovered on the next pass.
            for entry in self.parameters.values():
                for found_url in entry['urls']:
                    if '?' in found_url and self._same_domain(found_url) \
                            and found_url not in self._seen_pages:
                        queue.append(found_url)
                        break

        # Mine the collected script files
        for script_url in self._script_urls[:self.max_scripts]:
            response = self._get(script_url)
            if response is None or response.status_code >= 400:
                continue
            try:
                self.extract_from_js(response.text, source='external-js')
            except Exception:
                continue

    def _build_probe_url(self, name):
        """Append a candidate parameter set to the canary value."""
        try:
            parts = urlsplit(self.base_url)
            existing = parse_qsl(parts.query, keep_blank_values=True)
            existing.append((name, self.CANARY))
            query = urlencode(existing, doseq=True)
            return parts._replace(query=query).geturl()
        except Exception:
            return None

    def probe_parameters(self, baseline, candidates=None):
        """Confirm parameters by differential response analysis.

        For each candidate the parameter is added to the baseline URL with a
        canary value. A change in status code, a clearly different body size,
        or the canary being echoed back means the application reacted to it.
        """
        if not baseline:
            return

        names = candidates or list(self.parameters.keys())
        checked = 0

        for name in names:
            if checked >= self.probe_limit:
                break
            entry = self.parameters.get(name)
            if entry is None:
                continue

            probe_url = self._build_probe_url(name)
            if not probe_url:
                continue

            checked += 1
            response = self._get(probe_url)
            if response is None:
                continue

            body = response.text or ''
            status_differs = response.status_code != baseline['status']
            length_delta = abs(len(body) - baseline['length'])
            # A tolerance avoids flagging trivial dynamic-size differences
            size_differs = length_delta > max(50, baseline['length'] * 0.02)
            echoed = self.CANARY in body

            if echoed:
                entry['live'] = True
                entry['live_confidence'] = 'high'
            elif status_differs or size_differs:
                entry['live'] = True
                entry['live_confidence'] = 'medium'
            else:
                entry['live'] = False
                entry['live_confidence'] = 'low'

            entry['probe_delta'] = length_delta
            time.sleep(0.05)


    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def build_findings(self):
        """Turn discovered parameters into findings, highlighting risk."""
        params = self._flush()
        if not params:
            return self.findings

        # Summary of everything that was found
        names = sorted(entry['name'] for entry in params)
        self.findings.append({
            'type': 'Information Disclosure',
            'severity': 'Info',
            'title': f'Discovered {len(params)} URL parameter(s)',
            'description': (
                f'Found {len(params)} parameter(s) accepted by the application: '
                f'{", ".join(names[:30])}'
                + ('...' if len(names) > 30 else '')
            ),
            'url': self.base_url,
            'parameter_count': len(params),
            'parameters': names,
            'remediation': (
                'Review whether every parameter is required and expected. '
                'Undocumented parameters increase attack surface and may expose '
                'hidden functionality.'
            ),
        })

        # Live (confirmed) parameters are the actionable ones
        live = [e for e in params if e.get('live')]
        if live:
            self.findings.append({
                'type': 'Configuration',
                'severity': 'Low',
                'title': f'{len(live)} parameter(s) confirmed as processed',
                'description': (
                    'The server response changed when these parameters were '
                    f'supplied, indicating they are handled: '
                    f'{", ".join(sorted(e["name"] for e in live))}'
                ),
                'url': self.base_url,
                'parameters': sorted(e['name'] for e in live),
                'remediation': (
                    'Confirm each parameter is intended for public use and is '
                    'validated server-side.'
                ),
            })

        # Parameters that look like they carry secrets deserve attention
        sensitive = [
            e for e in params
            if e['type'] == 'auth' or any(
                marker in e['name'].lower()
                for marker in ('token', 'key', 'secret', 'pass', 'auth', 'session')
            )
        ]
        if sensitive:
            self.findings.append({
                'type': 'Sensitive Data Exposure',
                'severity': 'Medium',
                'title': f'{len(sensitive)} sensitive-looking parameter(s) found',
                'description': (
                    'These parameters suggest the application accepts '
                    'authentication or secret material as URL input: '
                    f'{", ".join(sorted(e["name"] for e in sensitive))}. '
                    'Values passed in URLs are commonly logged, cached and '
                    'leaked via the Referer header.'
                ),
                'url': self.base_url,
                'parameters': sorted(e['name'] for e in sensitive),
                'remediation': (
                    'Never pass credentials or tokens in query strings. Use an '
                    'Authorization header, and make sure sensitive parameters '
                    'are stripped from logs and the Referer header.'
                ),
            })


        # Redirect-style parameters are a common open-redirect sink
        redirects = [e for e in params if e['type'] == 'redirect']
        if redirects:
            self.findings.append({
                'type': 'Configuration',
                'severity': 'Info',
                'title': f'{len(redirects)} redirect/URL parameter(s) detected',
                'description': (
                    'These parameters accept a destination URL and are common '
                    'open-redirect sinks: '
                    f'{", ".join(sorted(e["name"] for e in redirects))}'
                ),
                'url': self.base_url,
                'parameters': sorted(e['name'] for e in redirects),
                'remediation': (
                    'Validate redirect targets against an allowlist of trusted '
                    'hosts to prevent open redirect abuse.'
                ),
            })

        # File/path parameters are a classic LFI sink
        file_params = [e for e in params if e['type'] == 'file']
        if file_params:
            self.findings.append({
                'type': 'Configuration',
                'severity': 'Info',
                'title': f'{len(file_params)} file/path parameter(s) detected',
                'description': (
                    'These parameters accept a filename or path and should be '
                    'tested for local file inclusion: '
                    f'{", ".join(sorted(e["name"] for e in file_params))}'
                ),
                'url': self.base_url,
                'parameters': sorted(e['name'] for e in file_params),
                'remediation': (
                    'Map requested files against an allowlist and reject path '
                    'traversal sequences.'
                ),
            })

        return self.findings

    def scan(self):
        """Main scanning function - discover parameters across the target."""
        try:
            # 1. The target URL itself
            self.extract_from_url(self.base_url, source='target-url')
            self.extract_path_params(self.base_url)

            # 2. Crawl for links, forms and scripts
            self.crawl()

            # 3. If nothing surfaced, fall back to the common wordlist
            if not self.parameters:
                for name in self.COMMON_PARAMS:
                    self.record(name, 'query', None, self.base_url, 'GET',
                                'wordlist')

            # 4. Confirm what the application actually processes
            baseline = self._baseline()
            if baseline is not None:
                self.probe_parameters(baseline)

            # 5. Report
            self.build_findings()

        except Exception as e:
            self.findings.append({
                'type': 'Error',
                'severity': 'Info',
                'title': 'Parameter discovery failed',
                'description': f'Scanning error: {str(e)}',
                'url': self.base_url,
                'remediation': 'Verify the target is reachable and retry.',
            })

        return self.findings

