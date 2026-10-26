"""
Proof-of-Concept (PoC) Evidence

Findings record a URL, a parameter and sometimes the payload, but not the
request that was sent or the response that came back. That makes a finding
hard to act on: you cannot tell exactly where it happened, and you cannot see
the response that proved it.

This module closes that gap without touching the individual scanners. It
supplies a `RecordingSession` that behaves exactly like `requests.Session` but
also captures every request/response pair, and then correlates those captures
with the findings a scanner produced.

For each finding it produces:

  * `location` - method, full URL, endpoint, and the parameter
  * `request`  - headers, body, and a copy-pasteable curl command
  * `response` - status, headers, and the body excerpt around the marker
  * a marker  - the exact payload/pattern found in the response, with offset

Safety:
  * Captures are bounded and bodies truncated, so a long scan cannot exhaust
    memory or bloat the report.
  * Credential headers (Authorization, Cookie, API keys) are redacted before
    anything is stored, so a report can be shared without leaking secrets.
"""

import re
import threading
from urllib.parse import urlparse, parse_qsl

import requests

# Bound the memory a single scan can use for evidence
MAX_EXCHANGES = 500
# Bodies are truncated on the way in: the report only ever shows a short
# excerpt, so holding whole pages in the buffer is wasted memory.
BUFFERED_BODY_LIMIT = 4000
BODY_EXCERPT_LIMIT = 2000
# How much text to show either side of a marker inside the response
MARKER_CONTEXT = 220

# Headers that must never be written into a report
SENSITIVE_HEADERS = {
    'authorization', 'proxy-authorization', 'cookie', 'set-cookie',
    'x-api-key', 'x-auth-token', 'x-csrf-token', 'x-xsrf-token',
}

# Header names worth keeping on a request, for reproducibility
INTERESTING_REQUEST_HEADERS = (
    'content-type', 'accept', 'user-agent', 'referer', 'origin',
    'x-requested-with', 'cookie', 'authorization',
)

INTERESTING_RESPONSE_HEADERS = (
    'content-type', 'server', 'location', 'set-cookie', 'x-powered-by',
    'content-length', 'cache-control', 'x-frame-options',
    'content-security-policy', 'strict-transport-security',
)


def _redact_headers(headers):
    """Copy headers, replacing credential values with a marker."""
    safe = {}
    for name, value in (headers or {}).items():
        if name.lower() in SENSITIVE_HEADERS:
            safe[name] = '<redacted>'
        else:
            safe[name] = value
    return safe


def _pick(headers, names):
    """Select a subset of headers, keeping sensitive ones redacted."""
    result = {}
    for name, value in (headers or {}).items():
        if name.lower() in names:
            result[name] = '<redacted>' if name.lower() in SENSITIVE_HEADERS \
                else value
    return result


def _excerpt(text, marker=None, limit=BODY_EXCERPT_LIMIT):
    """Return a bounded excerpt, centred on the marker when there is one."""
    if not text:
        return ''
    if marker and marker in text:
        index = text.find(marker)
        start = max(0, index - MARKER_CONTEXT)
        end = min(len(text), index + len(marker) + MARKER_CONTEXT)
        excerpt = text[start:end]
        prefix = '...' if start > 0 else ''
        suffix = '...' if end < len(text) else ''
        return f'{prefix}{excerpt}{suffix}'
    return text[:limit] + ('...' if len(text) > limit else '')


def _build_curl(method, url, headers, body):
    """Render a copy-pasteable curl command for reproducing the request."""
    parts = ['curl', '-i', '-X', method.upper()]
    for name, value in (headers or {}).items():
        if value == '<redacted>':
            # Keep the shape without exposing the secret
            parts += ['-H', f'{name}: <your-value-here>']
        else:
            parts += ['-H', f'{name}: {value}']
    if body:
        parts += ['--data', f"'{body}'"]
    parts.append(f"'{url}'")
    return ' '.join(parts)


class RecordingSession(requests.Session):
    """A requests.Session that also records every exchange it performs.

    Drop-in replacement for requests.Session, so a scanner needs no changes to
    produce evidence.
    """

    def __init__(self, max_exchanges=MAX_EXCHANGES):
        super().__init__()
        self.max_exchanges = max_exchanges
        self._exchanges = []
        self._lock = threading.Lock()

    def request(self, method, url, **kwargs):
        """Perform the request, then record it.

        Recording never breaks the caller: a failure to capture is swallowed so
        a scanner cannot be failed by its own evidence collection.
        """
        try:
            response = super().request(method, url, **kwargs)
        except Exception:
            # Still record the attempt - a connection error is evidence too
            self._record(method, url, kwargs, None)
            raise

        self._record(method, url, kwargs, response)
        return response

    def _record(self, method, url, kwargs, response):
        try:
            text = getattr(response, 'text', '') or ''
            with self._lock:
                self._exchanges.append({
                    'method': method.upper(),
                    'url': url,
                    'request_headers': _redact_headers(kwargs.get('headers')),
                    'request_body': kwargs.get('data') or kwargs.get('json'),
                    'status': getattr(response, 'status_code', None),
                    'response_headers': _pick(
                        getattr(response, 'headers', None),
                        INTERESTING_RESPONSE_HEADERS),
                    'body': text[:BUFFERED_BODY_LIMIT],
                    'body_length': len(text),
                })
                # Keep memory bounded during long scans
                if len(self._exchanges) > self.max_exchanges:
                    del self._exchanges[:-self.max_exchanges]
        except Exception:
            pass

    @property
    def exchanges(self):
        """Snapshot of recorded exchanges (thread-safe)."""
        with self._lock:
            return list(self._exchanges)

    def clear(self):
        with self._lock:
            self._exchanges = []


def _path_of(url):
    try:
        parsed = urlparse(url)
        return parsed.path or '/'
    except Exception:
        return url or ''


def _match_exchange(finding, exchanges):
    """Find the exchange that produced a finding.

    Preference order:
      1. a request that carried the finding's payload (the real test)
      2. an exact URL match
      3. the same endpoint/path
    """
    if not exchanges:
        return None, None

    url = finding.get('url') or ''
    payload = finding.get('payload')
    path = _path_of(url)

    if payload:
        for exchange in exchanges:
            # The payload may be URL-encoded in the request
            if str(payload) in exchange['url']:
                return exchange, 'exact-payload'

    for exchange in exchanges:
        if exchange['url'] == url:
            return exchange, 'exact-url'

    for exchange in exchanges:
        if _path_of(exchange['url']) == path:
            return exchange, 'same-endpoint'

    return None, None


def _baseline_for(exchange, exchanges):
    """Find the clean request to the same endpoint, for comparison."""
    if not exchange:
        return None
    path = _path_of(exchange['url'])
    base = exchange['url'].split('?')[0]

    for candidate in exchanges:
        if candidate is exchange:
            continue
        if candidate['url'] == base and _path_of(candidate['url']) == path:
            return candidate
    return None


def _find_marker(finding, exchange):
    """Work out what in the response actually proved the vulnerability."""
    body = exchange.get('body') or ''
    payload = finding.get('payload')

    # A reflected payload appearing verbatim is the strongest proof
    if payload and str(payload) in body:
        index = body.find(str(payload))
        return {
            'type': 'reflected-payload',
            'value': str(payload)[:200],
            'offset': index,
            'description': (
                f'The payload was reflected verbatim in the response body at '
                f'offset {index}.'
            ),
        }

    # An error/pattern string the scanner recorded
    evidence = finding.get('evidence')
    if evidence:
        # Scanners write things like "Pattern matched: <script>" or
        # "Error pattern: you have an error in your sql syntax"
        snippet = str(evidence)
        match = re.split(r':\s*', snippet, maxsplit=1)
        candidate = match[-1] if len(match) > 1 else snippet
        if candidate and candidate in body:
            index = body.find(candidate)
            return {
                'type': 'pattern-match',
                'value': candidate[:200],
                'offset': index,
                'description': f'Matched in the response body at offset {index}.',
            }
        return {
            'type': 'scanner-evidence',
            'value': snippet[:200],
            'offset': None,
            'description': snippet,
        }

    # No explicit marker: the captured exchange is the evidence
    return {
        'type': 'response',
        'value': None,
        'offset': None,
        'description': (
            'No specific payload marker was recorded for this finding; the '
            'captured request and response are shown below.'
        ),
    }


def build_poc(finding, exchanges):
    """Build the PoC block for one finding.

    Always returns a usable block, even when no exchange was captured, so the
    UI can show the known location and say the response was not recorded.
    """
    url = finding.get('url') or ''
    parameter = finding.get('parameter')

    location = {
        'url': url,
        'endpoint': url.split('?')[0] if url else '',
        'method': 'GET',
        'parameter': parameter,
        'query': dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        if '?' in url else {},
    }

    exchange, match_type = _match_exchange(finding, exchanges or [])

    if not exchange:
        return {
            'available': False,
            'match': match_type,
            'reason': 'No matching HTTP exchange was recorded for this finding.',
            'location': location,
            'marker': None,
        }

    location['method'] = exchange['method']
    # The recorded URL is the exact one that was requested
    location['request_url'] = exchange['url']
    location['query'] = dict(
        parse_qsl(urlparse(exchange['url']).query, keep_blank_values=True)
    ) if '?' in exchange['url'] else {}

    marker = _find_marker(finding, exchange)
    baseline = _baseline_for(exchange, exchanges or [])

    request_headers = _pick(exchange.get('request_headers'),
                            INTERESTING_REQUEST_HEADERS)
    body = exchange.get('body') or ''

    return {
        'available': True,
        'match': match_type,
        'location': location,
        'request': {
            'method': exchange['method'],
            'url': exchange['url'],
            'headers': request_headers,
            'body': exchange.get('request_body'),
            'curl': _build_curl(exchange['method'], exchange['url'],
                                request_headers, exchange.get('request_body')),
        },
        'response': {
            'status': exchange.get('status'),
            'headers': exchange.get('response_headers') or {},
            'body_length': exchange.get('body_length', len(body)),
            'excerpt': _excerpt(body, marker.get('value') if marker else None),
            'truncated': exchange.get('body_length', len(body)) > BODY_EXCERPT_LIMIT,
        },
        'marker': marker,
        'baseline': ({
            'url': baseline['url'],
            'status': baseline.get('status'),
            'body_length': len(baseline.get('body') or ''),
        } if baseline else None),
    }


def attach_poc(findings, exchanges):
    """Attach a PoC block to every finding that has a location."""
    if not findings:
        return findings
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        try:
            finding['poc'] = build_poc(finding, exchanges)
        except Exception:
            # Evidence must never break reporting
            finding['poc'] = {'available': False,
                              'reason': 'Evidence collection failed.'}
    return findings


def fill_missing_poc(findings, exchanges):
    """Attach evidence only to findings that do not already have it.

    The scan runner attaches evidence per module while that module's requests
    are still in the buffer. By the end of a long scan the buffer has rolled
    over, so re-running attach_poc() on everything would replace good evidence
    with "not found". This only tops up the gaps.
    """
    if not findings:
        return findings
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        existing = finding.get('poc')
        if isinstance(existing, dict) and existing.get('available'):
            continue
        try:
            finding['poc'] = build_poc(finding, exchanges)
        except Exception:
            continue
    return findings


def summarise(pocs):
    """Counts for a report header: how many findings carry evidence."""
    total = len(pocs)
    with_response = sum(1 for p in pocs if p.get('available'))
    return {
        'total': total,
        'with_evidence': with_response,
        'without_evidence': total - with_response,
    }
