"""
Finding Deduplication

A single scan routinely reports the same vulnerability several times:

  * the same class found by two modules (the dedicated one and the "web"
    group both cover WordPress, XXE, SSTI, ...)
  * the same class at the same parameter, proven with several different
    payloads (XSS has a long payload list and reports the first hit)
  * identical findings emitted by a scanner for each page of a crawl

The previous check compared the raw URL, which embeds the injected payload, so
`?q=<script>alert(1)</script>` and `?q=<script>alert(2)</script>` never
matched and every variant survived.

This module normalises a finding to a stable identity - vulnerability class,
endpoint with parameter values stripped, and the parameter name - then merges
everything sharing that identity. Nothing is discarded silently: payloads,
evidence and alternative descriptions are collected, the strongest severity
wins, and the best proof of concept is kept.
"""

import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

# Severity ranking, most severe first
SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info', 'None', 'Good']
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}

# Canonical vulnerability classes, keyed by the normalised scanner type.
CLASS_ALIASES = {
    'sqli': 'SQL Injection',
    'sql injection': 'SQL Injection',
    'sql injection (sqli)': 'SQL Injection',
    'sql injection error-based': 'SQL Injection',
    'xss': 'Cross-Site Scripting (XSS)',
    'cross-site scripting': 'Cross-Site Scripting (XSS)',
    'cross-site scripting (xss)': 'Cross-Site Scripting (XSS)',
    'cross site scripting (xss)': 'Cross-Site Scripting (XSS)',
    'reflected xss': 'Cross-Site Scripting (XSS)',
    'idor': 'Insecure Direct Object Reference (IDOR)',
    'insecure direct object reference': 'Insecure Direct Object Reference (IDOR)',
    'insecure direct object reference (idor)': 'Insecure Direct Object Reference (IDOR)',
    'lfi': 'Local File Inclusion (LFI)',
    'lfi/rfi': 'Local File Inclusion (LFI)',
    'local file inclusion': 'Local File Inclusion (LFI)',
    'local file inclusion (lfi)': 'Local File Inclusion (LFI)',
    'rfi': 'Remote File Inclusion (RFI)',
    'remote file inclusion': 'Remote File Inclusion (RFI)',
    'command injection': 'Command Injection',
    'os command injection': 'Command Injection',
    'os command injection (rce)': 'Command Injection',
    'file upload': 'Insecure File Upload',
    'insecure file upload': 'Insecure File Upload',
    'file upload vulnerability': 'Insecure File Upload',
    'open redirect': 'Open Redirect',
    'unvalidated redirect': 'Open Redirect',
    'ssrf': 'Server-Side Request Forgery (SSRF)',
    'server-side request forgery': 'Server-Side Request Forgery (SSRF)',
    'server-side request forgery (ssrf)': 'Server-Side Request Forgery (SSRF)',
    'xxe': 'XML External Entity (XXE)',
    'xxe injection': 'XML External Entity (XXE)',
    'xml external entity': 'XML External Entity (XXE)',
    'xml external entity (xxe)': 'XML External Entity (XXE)',
    'ssti': 'Server-Side Template Injection (SSTI)',
    'server-side template injection': 'Server-Side Template Injection (SSTI)',
    'server-side template injection (ssti)': 'Server-Side Template Injection (SSTI)',
    'deserialization': 'Insecure Deserialization',
    'insecure deserialization': 'Insecure Deserialization',
    'graphql': 'GraphQL',
    'wordpress': 'WordPress',
    'joomla': 'Joomla',
    'drupal': 'Drupal',
    'configuration': 'Configuration',
    'information disclosure': 'Information Disclosure',
    'missing security header': 'Configuration',
    'missing security headers': 'Configuration',
    'insecure cookie configuration': 'Configuration',
    'sensitive information disclosure': 'Information Disclosure',
    'sensitive data exposure': 'Sensitive Data Exposure',
}

# Cap on how many payloads we keep for a merged finding
MAX_PAYLOADS = 10

def severity_rank(severity):
    """Lower rank means more severe; unknown values sort last."""
    return SEVERITY_RANK.get(severity, len(SEVERITY_ORDER))


def canonical_class(finding):
    """Map a scanner's type string onto a stable vulnerability class."""
    raw = (finding.get('type') or finding.get('vulnerability') or '').strip()
    if not raw:
        return 'Unknown'
    key = raw.lower().strip()
    if key in CLASS_ALIASES:
        return CLASS_ALIASES[key]
    # Strip a trailing parenthesised qualifier and retry
    stripped = re.sub(r'\s*\([^)]*\)\s*$', '', key).strip()
    if stripped in CLASS_ALIASES:
        return CLASS_ALIASES[stripped]
    return raw.strip()


def normalize_url(url, include_query=True):
    """Normalise a URL so the same endpoint always yields the same string.

    Parameter values are replaced with '*' because the same vulnerability is
    usually proven with several different payloads, and those payloads would
    otherwise make every variant look like a different location.

    `include_query` is switched off when the parameter is tracked separately,
    since the query then carries no extra information and only splits
    otherwise-identical findings.
    """
    if not url:
        return ''
    try:
        parts = urlparse(url.strip())
    except Exception:
        return url.strip().lower()

    scheme = (parts.scheme or '').lower()
    netloc = (parts.netloc or '').lower()
    # Drop a default port so host:80 and host are the same endpoint
    if netloc.endswith(':80') and scheme in ('', 'http'):
        netloc = netloc[:-3]
    elif netloc.endswith(':443') and scheme == 'https':
        netloc = netloc[:-4]

    path = (parts.path or '').rstrip('/') or '/'

    query = ''
    if parts.query and include_query:
        try:
            pairs = parse_qsl(parts.query, keep_blank_values=True)
            # Keep the names, discard the values
            query = urlencode([(name, '*') for name, _ in pairs])
        except Exception:
            query = '*'

    return urlunparse((scheme, netloc, path, '', query, ''))


def _param_key(finding):
    """Identify the parameter, falling back to the recorded location."""
    param = (finding.get('parameter') or '').strip()
    if param:
        return param.lower()
    poc = finding.get('poc') or {}
    location = poc.get('location') or {}
    return (location.get('parameter') or '').strip().lower()


def _url_key(finding):
    """Best available URL for identity: the exact request, else the raw url."""
    poc = finding.get('poc') or {}
    location = poc.get('location') or {}
    request = poc.get('request') or {}
    return (
        request.get('url')
        or location.get('request_url')
        or finding.get('url')
        or ''
    )


def identity(finding):
    """Stable identity of a finding: class + normalised location + parameter.

    When the parameter is known it is compared separately, so the query string
    is dropped from the location - otherwise a finding recorded against the
    bare endpoint and one recorded against the URL carrying the original query
    would never match. When no parameter is known, the query parameter names
    are still used to tell locations apart.
    """
    if not isinstance(finding, dict):
        return ('Invalid', '', '')
    parameter = _param_key(finding)
    return (
        canonical_class(finding),
        normalize_url(_url_key(finding), include_query=not parameter),
        parameter,
    )


def _poc_score(poc):
    """Rank proof-of-concept blocks so the most convincing one is kept."""
    if not isinstance(poc, dict) or not poc.get('available'):
        return -1
    score = 1
    marker_type = (poc.get('marker') or {}).get('type')
    if marker_type == 'reflected-payload':
        score += 3
    elif marker_type == 'pattern-match':
        score += 2
    elif marker_type == 'scanner-evidence':
        score += 1
    if poc.get('request', {}).get('curl'):
        score += 1
    if poc.get('response', {}).get('excerpt'):
        score += 1
    return score


def _append_unique(target, value, cap=None):
    """Append to a list only if the value is new, respecting an optional cap."""
    if value in (None, ''):
        return
    text = str(value)
    if text in target:
        return
    if cap is not None and len(target) >= cap:
        return
    target.append(text)


def _merge_into(primary, duplicate):
    """Fold a duplicate finding into the one being kept."""
    # The most severe rating wins
    if severity_rank(duplicate.get('severity')) < severity_rank(
            primary.get('severity')):
        primary['severity'] = duplicate.get('severity')

    # Keep a longer, more informative description
    if len(str(duplicate.get('description') or '')) > len(
            str(primary.get('description') or '')):
        primary['description'] = duplicate['description']

    # Prefer a remediation we do not already have
    if not primary.get('remediation') and duplicate.get('remediation'):
        primary['remediation'] = duplicate['remediation']

    # The primary finding's own values must be folded in too, otherwise a
    # merged finding would only report the payloads of its duplicates.
    payloads = primary.setdefault('payloads', [])
    _append_unique(payloads, primary.get('payload'), MAX_PAYLOADS)
    evidence = primary.setdefault('evidence_list', [])
    _append_unique(evidence, primary.get('evidence'))
    modules = primary.setdefault('modules', [])
    _append_unique(modules, primary.get('module'))
    variants = primary.setdefault('variants', [])

    # Collect every payload that proved the same issue
    _append_unique(payloads, duplicate.get('payload'), MAX_PAYLOADS)
    # The single-payload field stays pointing at something that worked
    if not primary.get('payload') and duplicate.get('payload'):
        primary['payload'] = duplicate['payload']

    # Collect distinct evidence strings
    _append_unique(evidence, duplicate.get('evidence'))

    # Record the alternative descriptions instead of losing them
    title = duplicate.get('title')
    if title and title != primary.get('title') and title not in variants:
        variants.append(title)

    # Remember which modules reported it
    _append_unique(modules, duplicate.get('module'))

    # Keep the most convincing proof of concept
    if _poc_score(duplicate.get('poc')) > _poc_score(primary.get('poc')):
        primary['poc'] = duplicate['poc']

    primary['merged_count'] = primary.get('merged_count', 0) + 1


def _group(findings, key_func):
    """Group findings by key_func, merging collisions. Returns (list, index)."""
    grouped = []
    index = {}
    invalid = 0
    for finding in findings:
        if not isinstance(finding, dict):
            invalid += 1
            continue
        key = key_func(finding)
        # A key of None means the finding cannot be safely collapsed
        if key is not None and key in index:
            _merge_into(grouped[index[key]], finding)
        else:
            index[key] = len(grouped)
            grouped.append(dict(finding))
    return grouped, invalid


def _loose_key(finding):
    """Second-chance identity for the same test reported twice.

    Some scanners report a finding against both the bare endpoint and the URL
    carrying the target's original query string. Those are the same test, so
    they collapse - but only when the payload is identical, which proves the
    same request was made twice. Without a payload this pass is skipped,
    because the query string would be the only thing telling two genuinely
    different locations apart.
    """
    payload = str(finding.get('payload') or '').strip()
    if not payload:
        return None
    return (
        canonical_class(finding),
        normalize_url(_url_key(finding), include_query=False),
        _param_key(finding),
        payload,
    )


def dedupe_findings(findings):
    """Collapse duplicate findings, merging rather than discarding.

    Two passes: the first groups on vulnerability class, normalised location
    and parameter. The second collapses findings that share an identical
    payload at the same endpoint, which catches a scanner reporting the same
    test against both the bare endpoint and the query-carrying URL.

    Returns (unique_findings, stats).
    """
    if not findings:
        return [], {'original': 0, 'unique': 0, 'merged': 0, 'invalid_skipped': 0}

    original = len(findings)
    unique, invalid = _group(findings, identity)
    unique, _ = _group(unique, _loose_key)

    # Drop empty bookkeeping fields so the payload stays clean
    for finding in unique:
        for field in ('payloads', 'evidence_list', 'variants', 'modules'):
            if not finding.get(field):
                finding.pop(field, None)

    stats = {
        'original': original,
        'unique': len(unique),
        'merged': original - len(unique) - invalid,
        'invalid_skipped': invalid,
    }
    return unique, stats


def sort_findings(findings):
    """Order findings most severe first, so the worst issues surface first."""
    return sorted(
        findings,
        key=lambda f: (
            severity_rank(f.get('severity')),
            # Critical and High first, then alphabetical for stability
            str(f.get('type', '')),
        ),
    )
