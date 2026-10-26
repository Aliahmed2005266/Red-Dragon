"""
URL helpers shared by the scanner modules.

The scanners build test URLs by appending a parameter to a base URL, and the
naive way of doing that - an f-string like f"{base_url}?{param}=1" - produces a
malformed URL whenever the base already carries a query string. Scanning
"http://host/search?q=test" would then request

    http://host/search?q=test?param=1

where the second "?" becomes part of the value of a parameter rather than
starting a new query, so the injected value never reaches the application and
the test silently reports nothing.

Users routinely paste URLs that include a query string, so this quietly
degraded every parameter-guessing module. These helpers append correctly.
"""

from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode, quote


def with_param(url, name, value, replace=True):
    """Return `url` with a single query parameter set.

    Adds `?name=value` when the URL has no query, and `&name=value` when it
    already has one.

    `replace` defaults to True because every caller here is a probe: a test has
    to overwrite the real value, not sit behind it. Scanning "?q=1" with a probe
    for "q" would otherwise produce "?q=1&q=payload", and an application that
    reads the first value would never see the payload - a silent false negative.

    The value is percent-encoded, so payloads containing `&`, `#` or spaces
    cannot corrupt the rest of the URL.
    """
    if not url:
        return url
    try:
        parts = urlparse(url)
    except Exception:
        return url

    existing = parse_qsl(parts.query, keep_blank_values=True)
    if replace:
        existing = [(k, v) for k, v in existing if k != name]

    query = urlencode(existing + [(name, value)], doseq=True)

    # urlunparse drops an empty path, so make sure there is always one
    path = parts.path or "/"
    return urlunparse((parts.scheme, parts.netloc, path, parts.params,
                       query, parts.fragment))


def base_without_query(url):
    """Return the URL with its query string removed.

    Used when a scanner wants to probe a parameter against a clean endpoint
    rather than against whatever the target URL happened to carry.
    """
    if not url:
        return url
    try:
        parts = urlparse(url)
    except Exception:
        return url
    return urlunparse((parts.scheme, parts.netloc, parts.path or "/",
                       parts.params, "", ""))


def payload_url(base_url, name, value, replace=True):
    """Build a probe URL for `name`=`value` against `base_url`.

    Thin alias for `with_param` that names the intent at the call site.
    """
    return with_param(base_url, name, value, replace=replace)
