"""
Technology / Architecture Fingerprinting Module

Identifies what a target is actually built from, using multiple independent
signals rather than a single string match:

  * HTTP response headers   (Server, X-Powered-By, X-Runtime, Via, cookies)
  * Set-Cookie names         (PHPSESSID, JSESSIONID, laravel_session, ...)
  * Body content             (meta generator, asset paths, framework strings)
  * Error pages              (a 404 often leaks the framework outright)

Detected categories: web server, language/runtime, database, CMS, framework,
frontend library, CDN/WAF and hosting provider.

Every detection records the evidence that produced it and a confidence level,
because headers and generator tags are trivially spoofed and should not be
treated as proof on their own.
"""

import re

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover - bs4 is a hard requirement
    BeautifulSoup = None


# ---------------------------------------------------------------------------
# Signature tables. Each entry is (name, version_regex, confidence).
# confidence reflects how trustworthy the signal is on its own.
# ---------------------------------------------------------------------------

# Web server / reverse proxy
SERVER_SIGNATURES = [
    ('Nginx', r'nginx(?:/([\d.]+))?', 'high'),
    ('Apache', r'Apache(?:/([\d.]+))?', 'high'),
    ('Microsoft IIS', r'Microsoft-IIS(?:/([\d.]+))?', 'high'),
    ('LiteSpeed', r'LiteSpeed', 'high'),
    ('OpenResty', r'openresty(?:/([\d.]+))?', 'high'),
    ('Caddy', r'Caddy', 'high'),
    ('Apache Tomcat', r'Apache-Coyote|Tomcat(?:/([\d.]+))?', 'high'),
    ('Jetty', r'Jetty\(([\d.]+)\)', 'high'),
    ('gunicorn', r'gunicorn(?:/([\d.]+))?', 'high'),
    ('uvicorn', r'uvicorn', 'high'),
    ('Werkzeug', r'Werkzeug(?:/([\d.]+))?', 'high'),
    ('Phusion Passenger', r'Phusion Passenger(?:/([\d.]+))?', 'high'),
    ('Zope', r'Zope', 'high'),
    ('Kestrel', r'Kestrel', 'medium'),
    ('Varnish', r'varnish(?:/([\d.]+))?', 'high'),
    ('HAProxy', r'HAProxy(?:/([\d.]+))?', 'high'),
    ('AWS ELB', r'awselb|Elastic-Load-Balancer', 'high'),
    ('AkamaiGHost', r'AkamaiGHost|Akamai', 'high'),
    ('Tengine', r'Tengine(?:/([\d.]+))?', 'high'),
    ('Oracle HTTP Server', r'Oracle-HTTP-Server(?:/([\d.]+))?', 'high'),
    ('IBM WebSphere', r'IBM_HTTP_Server|WebSphere', 'high'),
]

# Language / runtime
LANGUAGE_SIGNATURES = [
    ('PHP', r'PHP(?:/([\d.]+))?', 'high'),
    ('Python', r'Python(?:/([\d.]+))?', 'high'),
    ('Ruby', r'Ruby(?:/([\d.]+))?', 'high'),
    ('Node.js', r'Node\.js(?: v?([\d.]+))?', 'high'),
    ('Java', r'Java(?:/([\d.]+))?', 'medium'),
    ('ASP.NET', r'ASP\.NET', 'high'),
    # 'Go' is deliberately omitted: it is far too common as a substring
    # (e.g. "googletagmanager", "logo") to be a reliable signal.
    ('Perl', r'Perl(?:/([\d.]+))?', 'high'),
    ('Lua', r'Lua(?:/([\d.]+))?', 'medium'),
    ('Elixir', r'Elixir', 'medium'),
    ('Erlang', r'Erlang', 'medium'),
    ('Kotlin', r'Kotlin', 'low'),
    ('Scala', r'Scala', 'low'),
    ('Swift', r'Swift', 'low'),
    ('Dart', r'Dart', 'low'),
    ('C#', r'ASP\.NET|CSharp', 'medium'),
    ('Rust', r'Rust', 'low'),
    ('XML', r'application/(?:xhtml\+xml|xml)\b|<\?xml\s+version', 'medium'),
]

# Databases / data stores
DATABASE_SIGNATURES = [
    ('MySQL', r'MySQL(?:/([\d.]+))?', 'high'),
    ('MariaDB', r'MariaDB(?:/([\d.]+))?', 'high'),
    ('PostgreSQL', r'PostgreSQL(?:/([\d.]+))?|Postgres', 'high'),
    ('Microsoft SQL Server', r'Microsoft SQL Server|MSSQL|SQL Server', 'high'),
    ('Oracle Database', r'Oracle(?: SQL| Database)|ORA-\d{5}', 'high'),
    ('SQLite', r'SQLite(?:/([\d.]+))?', 'high'),
    ('MongoDB', r'MongoDB(?:/([\d.]+))?', 'high'),
    ('Redis', r'Redis(?:/([\d.]+))?', 'high'),
    ('Memcached', r'Memcached', 'high'),
    ('Elasticsearch', r'Elasticsearch(?:/([\d.]+))?', 'high'),
    ('Cassandra', r'Cassandra(?:/([\d.]+))?', 'high'),
    ('CouchDB', r'CouchDB(?:/([\d.]+))?', 'high'),
    ('InfluxDB', r'InfluxDB(?:/([\d.]+))?', 'high'),
    ('ClickHouse', r'ClickHouse(?:/([\d.]+))?', 'medium'),
    ('Neo4j', r'Neo4j', 'medium'),
    ('Firebase', r'Firebase|firebaseio\.com', 'medium'),
    ('DynamoDB', r'DynamoDB', 'medium'),
    ('SQLAlchemy', r'SQLAlchemy', 'medium'),
    ('Prisma', r'Prisma', 'low'),
    ('Mongoose', r'Mongoose(?:/([\d.]+))?', 'medium'),
]

# CMS. The generator patterns also match bare header values such as
# "X-Generator: Drupal 10", not just a full <meta> tag.
CMS_SIGNATURES = [
    ('WordPress', r'WordPress\s*([\d.]+)', 'high'),
    ('Drupal', r'Drupal\s*(\d+(?:\.\d+)*)', 'high'),
    ('Joomla', r'Joomla!?\s*([\d.]+)', 'high'),
    ('Magento', r'Magento|var\s+MAGE', 'high'),
    ('Shopify', r'Shopify\.cdn|cdn\.shopify\.com', 'high'),
    ('Wix', r'wix\.com|wixstatic', 'high'),
    ('Squarespace', r'squarespace', 'high'),
    ('TYPO3', r'TYPO3', 'high'),
    ('MODX', r'MODX', 'high'),
    ('Craft CMS', r'Craft CMS', 'medium'),
    ('Ghost', r'ghost\.io|ghost-content', 'high'),
    ('Strapi', r'strapi', 'medium'),
    ('Contentful', r'contentful', 'medium'),
]

# Backend frameworks
FRAMEWORK_SIGNATURES = [
    ('Laravel', r'laravel_session|XSRF-TOKEN', 'high'),
    ('Symfony', r'symfony(?:/| )', 'high'),
    ('Django', r'csrfmiddlewaretoken|__admin_media_prefix__|DJANGO_SETTINGS', 'high'),
    ('Ruby on Rails', r'rails-ujs|_rails_session|__session', 'high'),
    ('Express', r'X-Powered-By:\s*Express|connect\.sid', 'high'),
    ('Spring Boot', r'Whitelabel Error Page|spring-boot', 'high'),
    ('ASP.NET MVC', r'ASP.NET_SessionId|__VIEWSTATE|__EVENTVALIDATION', 'high'),
    ('ASP.NET Core', r'Microsoft-IIS|AspNetCore', 'medium'),
    ('Node.js Koa', r'koa', 'low'),
    ('Flask', r'Werkzeug|flask', 'high'),
    ('FastAPI', r'fastapi', 'medium'),
    ('Deno', r'deno', 'low'),
    ('CodeIgniter', r'CI_SESSION', 'high'),
    ('CakePHP', r'cakephp', 'medium'),
    ('Yii', r'_csrf|yii_csrf', 'medium'),
    ('Ruby Sinatra', r'sinatra', 'medium'),
    ('Nuxt', r'__NUXT__', 'high'),
    ('Next.js', r'__NEXT_DATA__|_next/static', 'high'),
    ('Remix', r'__remixContext', 'medium'),
    ('Gatsby', r'___gatsby', 'high'),
    ('Astro', r'astro-island|data-astro', 'medium'),
]

# Frontend libraries
FRONTEND_SIGNATURES = [
    ('React', r'react(?:-dom)?(?:\.production|\.development)?(?:\.min)?\.js', 'high'),
    ('Vue.js', r'vue(?:\.runtime)?(?:\.min)?\.js', 'high'),
    ('Angular', r'ng-version|angular(?:\.min)?\.js|@angular', 'high'),
    ('Svelte', r'svelte-[a-z0-9]+|__svelte', 'high'),
    ('jQuery', r'jquery[.\-][\d.]*(?:\.min)?\.js', 'high'),
    ('Bootstrap', r'bootstrap(?:\.min)?\.(?:css|js)', 'high'),
    ('Tailwind CSS', r'tailwind(?:css)?(?:\.min)?\.css|__tw_config', 'high'),
    ('Foundation', r'foundation(?:\.min)?\.js', 'medium'),
    ('Material UI', r'material-ui|@material', 'medium'),
    ('Redux', r'redux(?:\.min)?\.js|__REDUX_DEVTOOLS', 'medium'),
    ('jQuery UI', r'jquery-ui', 'medium'),
    ('Font Awesome', r'font-?awesome', 'medium'),
    ('Google Analytics', r'google-analytics\.com|gtag\(|ga\(', 'high'),
    ('GTM', r'googletagmanager\.com', 'high'),
    ('Segment', r'segment\.com/analytics', 'medium'),
    ('Hotjar', r'hotjar\.com', 'medium'),
    ('Cloudflare Insights', r'cloudflareinsights\.com', 'medium'),
]

# CDN / WAF / proxy
INFRA_SIGNATURES = [
    ('Cloudflare', r'cloudflare|cf-ray|__cfduid', 'high'),
    ('Akamai', r'akamai|akam[a-z]*grn', 'high'),
    ('Fastly', r'fastly|x-served-by.*cache', 'high'),
    ('Amazon CloudFront', r'amz-cf-id|cloudfront', 'high'),
    ('Sucuri', r'Sucuri|x-sucuri-id', 'high'),
    ('Imperva Incapsula', r'incapsula|visid_incap|X-Iinfo', 'high'),
    ('AWS CloudFront', r'amz-cf-id', 'high'),
    ('Google Cloud', r'Google Frontend|gws', 'medium'),
    ('KeyCDN', r'keycdn', 'medium'),
    ('BunnyCDN', r'bunnycdn', 'medium'),
    ('Stackpath', r'stackpath', 'medium'),
]

# Cookie names -> technology. A cookie name is a strong, specific signal.
COOKIE_SIGNATURES = {
    'PHPSESSID': ('PHP', 'high'),
    'PHPSESS': ('PHP', 'high'),
    'ASP.NET_SessionId': ('ASP.NET', 'high'),
    'ASP.NET_SA': ('ASP.NET', 'high'),
    'JSESSIONID': ('Java', 'high'),
    'JSESSIONIDSSO': ('Java', 'high'),
    'laravel_session': ('Laravel', 'high'),
    'ci_session': ('CodeIgniter', 'high'),
    'cakephp': ('CakePHP', 'high'),
    'connect.sid': ('Express', 'high'),
    'Rack.session': ('Ruby on Rails', 'high'),
    '_session': ('Ruby on Rails', 'medium'),
    '_symfony': ('Symfony', 'high'),
    'yii_csrf': ('Yii', 'medium'),
    'PHPSESSID_secure': ('PHP', 'medium'),
    'AWSELBCORS': ('AWS Load Balancer', 'medium'),
    '_dyn_stat': ('Dynatrace', 'medium'),
    'JSESSIONIDSSO': ('Java', 'high'),
}

# Body content patterns that reveal a technology.
# Each entry is (label, pattern, technology, category, confidence).
BODY_SIGNATURES = [
    ('phpinfo()', r'phpinfo\(\)', 'PHP', 'languages', 'medium'),
    ('Django debug page', r'DJANGO_SETTINGS_MODULE|Request Method:.*Request URL:', 'Django', 'frameworks', 'high'),
    ('Laravel debug page', r'Whoops|Illuminate\\|laravel\.framework', 'Laravel', 'frameworks', 'high'),
    ('Rails debug page', r'Action Controller:|Routing Error|RAILS_ROOT', 'Ruby on Rails', 'frameworks', 'high'),
    ('Spring Whitelabel', r'Whitelabel Error Page|There was an unexpected error', 'Spring Boot', 'frameworks', 'high'),
    ('ASP.NET error page', r'Server Error in .* Application|ASP\.NET is configured', 'ASP.NET', 'frameworks', 'high'),
    ('MongoDB driver error', r'MongoError|MongoDB\.Driver', 'MongoDB', 'databases', 'high'),
    ('MySQL driver error', r'mysqli_real_connect|warning.*mysql|mysql_connect\(\)|MySQL\s+\d+\.\d+', 'MySQL', 'databases', 'medium'),
    ('PDO exception', r'PDOException|SQLSTATE\[[0-9A-Z]+\]', 'PHP', 'languages', 'medium'),
    ('PostgreSQL error', r'pg_query\(\)|PG::|Npgsql|PostgreSQL query failed', 'PostgreSQL', 'databases', 'medium'),
    ('Redis client', r'Redis::|Connection refused.*6379|redis\.connect', 'Redis', 'databases', 'medium'),
    ('Elastic client', r'elasticsearch|9200 in stdAddr', 'Elasticsearch', 'databases', 'medium'),
    ('SQL Server driver', r'SQL Server|ODBC Driver|Microsoft OLE DB', 'Microsoft SQL Server', 'databases', 'low'),
    ('Oracle driver', r'ORA-\d{5}|Oracle Client|OCI8', 'Oracle Database', 'databases', 'medium'),
    ('SQLite', r'SQLite(?:3)?\.\w*error|sqlite3', 'SQLite', 'databases', 'medium'),
    ('GraphQL', r'/graphql|__typename|ApolloClient', 'GraphQL API', 'apis', 'medium'),
    ('REST API', r'/api/v\d+', 'REST API', 'apis', 'low'),
    ('Swagger / OpenAPI', r'swagger-ui|openapi\.json|api-docs', 'Swagger / OpenAPI', 'apis', 'medium'),
    ('XML content', r'application/(?:xhtml\+xml|xml)\b|<\?xml\s+version', 'XML', 'languages', 'low'),
    ('Flask debugger', r'Werkzeug Debugger|__debugger__', 'Flask', 'frameworks', 'high'),
]


# Technologies that a matching cookie implies a framework (not just a runtime)
FRAMEWORK_COOKIE_TECHS = {
    'Laravel', 'CodeIgniter', 'CakePHP', 'Symfony', 'Yii', 'Express',
    'Ruby on Rails',
}


class TechFingerprint:
    """Identify the architecture behind a web target."""

    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.session = session
        self.findings = []

        # category -> list of detection records
        self.architecture = {
            'servers': [],
            'languages': [],
            'databases': [],
            'cms': [],
            'frameworks': [],
            'frontend': [],
            'infrastructure': [],
            'apis': [],
        }

        # Raw evidence retained for the report and for the UI
        self.evidence = {
            'headers': {},
            'cookies': [],
            'generator': None,
            'http_status': None,
            'error_page_signals': [],
        }

    # ------------------------------------------------------------------
    # Detection bookkeeping
    # ------------------------------------------------------------------

    def _add(self, category, name, version=None, confidence='low',
             evidence=None):
        """Record a detection, merging duplicates and keeping the best signal."""
        bucket = self.architecture.setdefault(category, [])
        for item in bucket:
            if item['name'].lower() == name.lower():
                # Keep the strongest confidence and any version we learned
                if confidence == 'high' or item['confidence'] != 'high':
                    item['confidence'] = confidence
                if version and not item.get('version'):
                    item['version'] = version
                if evidence and evidence not in item['evidence']:
                    item['evidence'].append(evidence)
                return item

        item = {
            'name': name,
            'version': version,
            'confidence': confidence,
            'evidence': [evidence] if evidence else [],
        }
        bucket.append(item)
        return item

    # Body text is truncated before matching to bound the work. This must be
    # large enough to contain a generator tag in the <head>.
    BODY_LIMIT = 400000

    def _match(self, signatures, text, category, limit=None):
        """Run a signature table against a block of text."""
        if not text:
            return
        if limit is None:
            limit = self.BODY_LIMIT
        try:
            snippet = text[:limit]
        except Exception:
            return
        for name, pattern, confidence in signatures:
            try:
                match = re.search(pattern, snippet, re.I)
            except re.error:
                continue
            if not match:
                continue
            version = match.group(1) if match.groups() else None
            start = max(0, match.start() - 20)
            evidence = snippet[start:match.end() + 20].strip()
            self._add(category, name, version, confidence, evidence[:80])

    def _match_named(self, signatures, text, limit=None):
        """Run (label, pattern, tech, category, confidence) body signatures."""
        if not text:
            return
        if limit is None:
            limit = self.BODY_LIMIT
        try:
            snippet = text[:limit]
        except Exception:
            return
        for label, pattern, tech, category, confidence in signatures:
            try:
                match = re.search(pattern, snippet, re.I)
            except re.error:
                continue
            if not match:
                continue
            start = max(0, match.start() - 20)
            evidence = snippet[start:match.end() + 20].strip()[:80]
            self._add(category, tech, None, confidence, evidence)
            self.evidence['error_page_signals'].append(label)

    # ------------------------------------------------------------------
    # Signal collection
    # ------------------------------------------------------------------

    def analyze_headers(self, headers):
        """Fingerprint the server and infrastructure from HTTP headers."""
        if not headers:
            return
        try:
            items = list(headers.items())
        except Exception:
            return

        self.evidence['headers'] = dict(items)
        joined = '\n'.join(f'{k}: {v}' for k, v in items)

        # The Server header is the single most useful signal
        server_value = ''
        for key, value in items:
            if key.lower() == 'server':
                server_value = value
                break
        if server_value:
            self._match(SERVER_SIGNATURES, server_value, 'servers', limit=200)
            # A version banner often reveals the runtime too
            self._match(LANGUAGE_SIGNATURES, server_value, 'languages', limit=200)
        else:
            # No Server header: the rest may still name a reverse proxy
            self._match(SERVER_SIGNATURES, joined, 'servers', limit=200)

        # Framework / runtime / proxy specific headers
        interesting = (
            'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
            'x-runtime', 'x-generator', 'x-drupal-cache', 'x-backend-server',
            'x-varnish', 'via', 'x-served-by', 'x-cache', 'cf-ray',
            'x-amz-cf-id', 'x-amz-request-id', 'x-laravel', 'x-symfony',
            'x-shopid', 'x-magento-tags',
        )
        for key, value in items:
            if key.lower() in interesting:
                blob = f'{key}: {value}'
                self._match(LANGUAGE_SIGNATURES, blob, 'languages', limit=200)
                self._match(SERVER_SIGNATURES, blob, 'servers', limit=200)
                self._match(INFRA_SIGNATURES, blob, 'infrastructure', limit=200)
                self._match(FRAMEWORK_SIGNATURES, blob, 'frameworks', limit=200)
                self._match(DATABASE_SIGNATURES, blob, 'databases', limit=200)
            if key.lower() == 'x-generator':
                self.evidence['generator'] = value
                self._match(CMS_SIGNATURES, value, 'cms', limit=200)

        # Always scan the whole header block for CDN / WAF markers
        self._match(INFRA_SIGNATURES, joined, 'infrastructure')

    def analyze_cookies(self, cookies):
        """Cookie names are a very specific signal (PHPSESSID, JSESSIONID...)."""
        if not cookies:
            return
        try:
            names = [c.name for c in cookies]
        except Exception:
            try:
                names = [getattr(c, 'name', str(c)) for c in cookies]
            except Exception:
                return

        self.evidence['cookies'] = [str(n) for n in names if n]

        # Cloudflare and friends set very recognisable cookies
        self._match(INFRA_SIGNATURES, ' '.join(str(n) for n in names),
                    'infrastructure')

        for name in names:
            for cookie_name, (tech, confidence) in COOKIE_SIGNATURES.items():
                if cookie_name not in str(name):
                    continue
                # A framework cookie implies more than a bare runtime
                category = 'frameworks' if tech in FRAMEWORK_COOKIE_TECHS \
                    else 'languages'
                self._add(category, tech, None, confidence, f'cookie: {name}')

    def analyze_body(self, body):
        """Fingerprint CMS, frameworks, databases and frontend libraries."""
        if not body:
            return
        try:
            snippet = body[:400000]
        except Exception:
            return

        # Meta generator tag is the classic CMS signal
        if BeautifulSoup is not None:
            try:
                soup = BeautifulSoup(snippet, 'html.parser')
                meta = soup.find(
                    'meta', attrs={'name': re.compile(r'generator', re.I)})
                if meta and meta.get('content'):
                    self.evidence['generator'] = meta.get('content')
            except Exception:
                pass
        else:
            gen = re.search(
                r'<meta[^>]+name=["\']?generator["\']?[^>]*content=["\']([^"\']+)',
                snippet, re.I)
            if gen:
                self.evidence['generator'] = gen.group(1)

        # Database and error-page signatures
        self._match_named(BODY_SIGNATURES, snippet)

        self._match(CMS_SIGNATURES, snippet, 'cms')
        self._match(FRAMEWORK_SIGNATURES, snippet, 'frameworks')
        self._match(FRONTEND_SIGNATURES, snippet, 'frontend')
        self._match(LANGUAGE_SIGNATURES, snippet, 'languages')
        self._match(DATABASE_SIGNATURES, snippet, 'databases')

        # Asset extensions are a weak but free signal
        for ext, tech in (
            ('.php', 'PHP'), ('.asp', 'ASP.NET'), ('.aspx', 'ASP.NET'),
            ('.jsp', 'Java'), ('.do', 'Java'), ('.py', 'Python'),
            ('.rb', 'Ruby'), ('.cgi', 'Perl'), ('.pl', 'Perl'),
        ):
            if ext in snippet.lower():
                self._add('languages', tech, None, 'low',
                          f'asset reference: {ext}')

    def probe_error_page(self):
        """Request a missing path; error pages often name the framework."""
        if not self.base_url:
            return
        url = self.base_url.rstrip('/') + '/__red_dragon_missing_404__.php'
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
        except Exception:
            return
        if response is None:
            return
        try:
            if response.status_code >= 400:
                body = response.text or ''
                self._match_named(BODY_SIGNATURES, body)
                self._match(FRAMEWORK_SIGNATURES, body, 'frameworks')
                self._match(LANGUAGE_SIGNATURES, body, 'languages')
        except Exception:
            return

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    @property
    def technologies(self):
        """Flat list of detected technology names.

        The scan runner keeps using this name, so CVE matching and any
        existing consumer of `detected_technologies` keeps working.
        """
        names = []
        for bucket in self.architecture.values():
            for item in bucket:
                if item['name'] not in names:
                    names.append(item['name'])
        return names

    def summary(self):
        """Human-readable one-line description of the stack."""
        parts = []

        def names(key):
            return [i['name'] for i in self.architecture.get(key, [])]

        servers = names('servers')
        languages = names('languages')
        dbs = names('databases')
        cms = names('cms')
        frameworks = names('frameworks')
        infra = names('infrastructure')

        if servers:
            parts.append('Server: ' + ', '.join(servers))
        if languages:
            parts.append('Language: ' + ', '.join(languages))
        if cms:
            parts.append('CMS: ' + ', '.join(cms))
        if frameworks:
            parts.append('Framework: ' + ', '.join(frameworks))
        if dbs:
            parts.append('Database: ' + ', '.join(dbs))
        if infra:
            parts.append('CDN/WAF: ' + ', '.join(infra))

        return ' | '.join(parts) if parts else 'No technologies identified'

    def has_database_evidence(self):
        """True when a data store was identified."""
        return bool(self.architecture.get('databases'))

    def _architecture_finding(self):
        total = sum(len(v) for v in self.architecture.values())
        return {
            'type': 'Technology Detected',
            'severity': 'Info',
            'title': f'Target architecture: {total} technology(ies) identified',
            'description': self.summary(),
            'url': self.base_url,
            'architecture': self.architecture,
            'evidence': self.evidence,
            'technologies': self.technologies,
            'remediation': (
                'Use this inventory to scope patch management and confirm all '
                'components are supported and up to date.'
            ),
        }

    def _database_finding(self):
        return {
            'type': 'Technology Detected',
            'severity': 'Info',
            'title': 'Database in use detected',
            'description': (
                'The following data store(s) were identified: '
                + ', '.join(
                    f"{i['name']}"
                    f"{' ' + i['version'] if i.get('version') else ''}"
                    f" ({i['confidence']} confidence)"
                    for i in self.architecture['databases']
                )
            ),
            'url': self.base_url,
            'databases': self.architecture['databases'],
            'remediation': (
                'Confirm the database is patched, access is restricted and it '
                'is not directly exposed to the internet.'
            ),
        }

    def build_findings(self):
        """Report the fingerprint as structured findings."""
        total = sum(len(v) for v in self.architecture.values())

        if not total:
            self.findings.append({
                'type': 'Information',
                'severity': 'Info',
                'title': 'No technology fingerprint identified',
                'description': (
                    'No server, language, database, CMS or framework could be '
                    'identified from the response headers, cookies or body.'
                ),
                'url': self.base_url,
                'remediation': 'Consider suppressing technology banners to reduce recon.',
            })
            return self.findings

        self.findings.append(self._architecture_finding())

        # A detected database is the most useful part of the report
        if self.has_database_evidence():
            self.findings.append(self._database_finding())

        # Version banners are a recon gift - report the first one we find
        for bucket in ('servers', 'languages', 'cms'):
            for item in self.architecture.get(bucket, []):
                if not item.get('version'):
                    continue
                self.findings.append({
                    'type': 'Information Disclosure',
                    'severity': 'Low',
                    'title': (
                        f'{item["name"]} version disclosed ({item["version"]})'
                    ),
                    'description': (
                        f'The target reveals its {item["name"]} version '
                        f'({item["version"]}), which speeds up exploit research '
                        f'against known CVEs.'
                    ),
                    'url': self.base_url,
                    'technology': item['name'],
                    'version': item['version'],
                    'remediation': (
                        'Suppress version banners in server configuration and '
                        'remove generator meta tags.'
                    ),
                })
                return self.findings

        return self.findings

    def scan(self):
        """Fingerprint the target and return findings."""
        try:
            try:
                response = self.session.get(self.base_url, timeout=10)
            except Exception:
                response = None

            if response is not None:
                self.evidence['http_status'] = response.status_code
                for analyzer, arg in (
                    (self.analyze_headers, getattr(response, 'headers', None)),
                    (self.analyze_cookies, getattr(response, 'cookies', None)),
                    (self.analyze_body, getattr(response, 'text', None)),
                ):
                    try:
                        analyzer(arg)
                    except Exception:
                        # A failure in one signal must not lose the others
                        continue

            # A 404 page is often the most revealing response on a site
            self.probe_error_page()

            self.build_findings()
        except Exception as e:
            self.findings.append({
                'type': 'Error',
                'severity': 'Info',
                'title': 'Technology fingerprint failed',
                'description': f'Fingerprinting error: {str(e)}',
                'url': self.base_url,
                'remediation': 'Verify the target is reachable and retry.',
            })

        return self.findings
