"""
Red Dragon - Desktop Application Bootstrap

This is the entry point the installed desktop application launches. The regular
`server.py` main block is a developer convenience; this module is the hardened
one that the Electron shell runs as a sidecar.

What it does differently, and why each matters for an installed app:

* Binds to 127.0.0.1 on a free port, never 0.0.0.0. The scanner makes outbound
  requests on the user's behalf, so it must not be reachable from the network.
* Requires a per-launch secret token on every /api call. A local HTTP service
  with no auth can be driven by any web page the user visits, which would turn
  a routine page load into an attack against a target of the attacker's
  choosing. The token is injected into the served page, so only the real app
  has it.
* Serves the built React UI from the same origin, so the app is same-origin and
  needs no CORS grant at all.
* Prints one machine-readable line on stdout so the shell learns the port and
  token the moment the service is ready.

Run standalone for debugging with:  python desktop.py
"""

import os
import sys
import json
import socket
import secrets
import argparse

# The desktop shell parses stdout looking for this marker.
READY_PREFIX = 'REDDRAGON_READY '

APP_VERSION = '1.0.0'


def _bundle_root():
    """Directory holding bundled resources, honouring the PyInstaller layout."""
    if getattr(sys, 'frozen', False):
        # one-folder build: resources sit beside the executable
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def find_ui_build():
    """Locate the compiled React app.

    Covers a source checkout, a PyInstaller 6 bundle (where data lands in the
    `_internal` folder that `sys._MEIPASS` points at), and a flat bundle with
    the build copied next to the executable.
    """
    root = _bundle_root()
    parent = os.path.dirname(root)

    candidates = []

    # PyInstaller 6 puts bundled data under sys._MEIPASS, which is `_internal`
    # for a one-folder build. This is the case that matters for the installer.
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass:
        candidates.append(os.path.join(meipass, 'ui'))

    # Beside the executable: a source checkout, or a flat bundle.
    candidates.append(os.path.join(root, 'ui'))
    candidates.append(os.path.join(root, 'frontend', 'build'))
    candidates.append(os.path.join(parent, 'frontend', 'build'))
    candidates.append(os.path.join(parent, 'ui'))

    for path in candidates:
        if os.path.isfile(os.path.join(path, 'index.html')):
            return os.path.abspath(path)
    return None


def pick_free_port(preferred=0):
    """Ask the OS for a free loopback port.

    Port 0 lets the kernel choose, which avoids the "address already in use"
    failure a fixed port hits whenever two copies of the app run side by side.
    """
    for _ in range(50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(('127.0.0.1', preferred))
            except OSError:
                preferred = 0
                continue
            return sock.getsockname()[1]
    raise RuntimeError('Could not find a free port to listen on')


# ---------------------------------------------------------------------------
# The launch token
# ---------------------------------------------------------------------------

# Issued once at startup; the desktop shell receives it on stdout.
APP_TOKEN = None


def issue_token():
    """Create the per-launch secret and remember it."""
    global APP_TOKEN
    APP_TOKEN = secrets.token_urlsafe(32)
    return APP_TOKEN


def _token_is_valid(candidate):
    """Constant-time compare so the token cannot be probed byte by byte."""
    if not APP_TOKEN or not candidate:
        return False
    return secrets.compare_digest(str(candidate), APP_TOKEN)


def install_guard(app):
    """Require the launch token on every API call.

    Implemented as a WSGI middleware rather than a Flask before_request hook
    so it is order-proof: a middleware is applied at wrap time and is active
    on every request after that, regardless of whether the wrapped Flask app
    has already handled traffic. This keeps the guard intact when a shared
    app instance is installed late by a test (see test_previous_token_stops_working).
    """
    if getattr(app, '_red_dragon_guard_installed', False):
        return app

    app.wsgi_app = _TokenGuardMiddleware(app.wsgi_app)
    app._red_dragon_guard_installed = True
    return app


class _TokenGuardMiddleware:
    """WSGI middleware that rejects unauthenticated requests to /api."""

    def __init__(self, inner):
        self._inner = inner

    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO') or '/'
        if path.startswith('/api/'):
            if _token_is_valid(environ.get('HTTP_X_RD_TOKEN', '')):
                return self._inner(environ, start_response)
            return self._reject(environ, start_response)
        return self._inner(environ, start_response)

    @staticmethod
    def _reject(environ, start_response):
        response = json.dumps({
            'error': 'Missing or invalid application token',
            'code': 'invalid_token',
        }).encode('utf-8')
        start_response('403 Forbidden', [
            ('Content-Type', 'application/json'),
            ('Content-Length', str(len(response))),
        ])
        return [response]


# ---------------------------------------------------------------------------
# Serving the UI
# ---------------------------------------------------------------------------

# The tag in index.html that the backend fills in with the launch token.
# A script element is used rather than an HTML comment because the production
# HTML minifier strips comments, which would leave the packaged app with no
# token and every API call would be rejected.
BOOTSTRAP_TAG = '<script id="red-dragon-bootstrap"></script>'

# Kept for backwards compatibility with older builds and with the tests.
INDEX_PLACEHOLDER = BOOTSTRAP_TAG


def _bootstrap_script(token, ui_dir):
    """Build the script that hands the page its token and runtime facts.

    The values are embedded as JSON rather than raw text, so a value holding
    quotes or backslashes cannot break out of the script block.
    """
    payload = {
        'token': token,
        'version': APP_VERSION,
        'platform': sys.platform,
        'uiDir': ui_dir,
    }
    return '<script id="red-dragon-bootstrap">window.__RED_DRAGON__=' + \
        json.dumps(payload) + ';</script>'


def _inject_bootstrap(html, token, ui_dir):
    """Insert the bootstrap script into the served page.

    Replaces the placeholder tag when it is present, and otherwise falls back
    to inserting just before </head>. The fallback matters: if a future build
    step ever strips the tag, the app would silently lose its token and every
    request would be rejected, so there is always a way in.
    """
    script = _bootstrap_script(token, ui_dir)

    if BOOTSTRAP_TAG in html:
        return html.replace(BOOTSTRAP_TAG, script, 1)

    if INDEX_PLACEHOLDER != BOOTSTRAP_TAG and INDEX_PLACEHOLDER in html:
        return html.replace(INDEX_PLACEHOLDER, script, 1)

    for marker in ('</head>', '</body>', '</html>'):
        at = html.lower().rfind(marker)
        if at != -1:
            return html[:at] + script + html[at:]

    # Nothing recognisable: prepend so the page still gets its token.
    return script + html


# Extensions the compiled interface loads. A request for one of these that does
# not exist is a genuine 404, not a client-side route.
ASSET_EXTENSIONS = (
    '.js', '.mjs', '.css', '.map', '.json', '.png', '.jpg', '.jpeg', '.gif',
    '.svg', '.ico', '.webp', '.woff', '.woff2', '.ttf', '.eot', '.txt',
)


def _looks_like_asset(path):
    """Whether a path names a build asset rather than a client-side route."""
    return path.lower().endswith(ASSET_EXTENSIONS)


def install_ui(app, ui_dir):
    """Serve the compiled React app from this same origin.

    Unknown non-API paths fall back to index.html so client-side routes keep
    working across a reload.
    """
    from flask import send_from_directory, abort

    # The compiled interface keeps its assets under <ui>/static/... and its page
    # references them as /static/.... Flask already registers a rule mapping
    # /static/<path> to <app.static_folder>/<path>, which by default points at
    # backend/static - a folder that does not exist.
    #
    # That rule is more specific than the catch-all below, so it won every
    # request: /static/js/main.<hash>.js came back as a 404, the page loaded but
    # never ran, and the window stayed black. Aiming the built-in rule at the
    # interface's own static directory makes it serve the real bundle, and
    # url_map has no supported rule-removal API, so repointing is the way.
    ui_static = os.path.join(ui_dir, 'static')
    app.static_folder = ui_static if os.path.isdir(ui_static) else None

    def _send_index():
        # Read the token at request time, not at install time. Caching it in the
        # closure would serve a stale value if the token is ever re-issued, and
        # the page would then hold a token the guard no longer accepts.
        token = APP_TOKEN
        try:
            with open(os.path.join(ui_dir, 'index.html'), 'r',
                      encoding='utf-8') as fh:
                html = fh.read()
        except OSError:
            abort(500)
        return _inject_bootstrap(html, token, ui_dir), 200, {
            'Content-Type': 'text/html; charset=utf-8',
            # Never cache the UI, or a stale token could be replayed.
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'X-Content-Type-Options': 'nosniff',
        }

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def _ui(path):
        if path.startswith('api/'):
            abort(404)

        if path:
            # normpath collapses ../ so a crafted path cannot escape ui_dir
            candidate = os.path.normpath(os.path.join(ui_dir, path))
            if candidate.startswith(ui_dir):
                if os.path.isfile(candidate):
                    return send_from_directory(ui_dir, path)
                # A missing asset must 404 rather than fall through to the
                # page: returning HTML for a .js request produces a confusing
                # "unexpected token <" error instead of a clear failure, and
                # a mistyped asset name would otherwise look like it worked.
                if _looks_like_asset(path):
                    abort(404)

        return _send_index()

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def create_desktop_app(require_token=True):
    """Build the Flask app the desktop shell talks to.

    Kept in a function so tests can build a throwaway instance without opening
    a socket.
    """
    from server import app as flask_app
    from config_store import get_store

    # server.py already calls register_extensions at import time. Detect that
    # by looking for a known endpoint rather than trusting a module flag, so a
    # re-import in a test session cannot register everything twice.
    if "fuzz_target" not in flask_app.view_functions:
        from server_extensions import register_extensions
        register_extensions(flask_app)

    if require_token:
        issue_token()
        install_guard(flask_app)
    else:
        global APP_TOKEN
        APP_TOKEN = ''

    ui_dir = find_ui_build()
    if ui_dir:
        install_ui(flask_app, ui_dir)

    flask_app.config['RED_DRAGON_TOKEN'] = APP_TOKEN
    flask_app.config['RED_DRAGON_UI_DIR'] = ui_dir
    flask_app.config['RED_DRAGON_VERSION'] = APP_VERSION
    flask_app.config['RED_DRAGON_STORE'] = get_store

    return flask_app, APP_TOKEN, ui_dir


def main():
    parser = argparse.ArgumentParser(description='Red Dragon desktop backend')
    parser.add_argument('--port', type=int, default=0,
                        help='Port to listen on (0 picks a free one)')
    parser.add_argument('--no-token', action='store_true',
                        help='Disable the launch token (development only)')
    parser.add_argument('--ready-file', default='',
                        help='Write the start-up handshake JSON to this file')
    args = parser.parse_args()

    flask_app, token, ui_dir = create_desktop_app(
        require_token=not args.no_token)
    port = pick_free_port(args.port)

    handshake = {
        'ready': True,
        'port': port,
        'token': token,
        'ui': bool(ui_dir),
        'version': APP_VERSION,
        'pid': os.getpid(),
    }
    line = json.dumps(handshake)

    # Announce readiness on stdout for the development case.
    try:
        sys.stdout.write(READY_PREFIX + line + '\n')
        sys.stdout.flush()
    except Exception:
        # A windowed build on Windows has no stdout at all, which is exactly
        # why --ready-file exists.
        pass

    # The packaged app is built with console=False, so on Windows it has no
    # stdout and the desktop shell would wait forever for the ready line.
    # Writing the handshake to a file the shell names is what makes the
    # installed app start reliably.
    if args.ready_file:
        try:
            parent = os.path.dirname(os.path.abspath(args.ready_file))
            if parent:
                os.makedirs(parent, exist_ok=True)
            tmp = args.ready_file + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as fh:
                fh.write(line)
            os.replace(tmp, args.ready_file)
        except Exception as exc:
            print(f"Could not write the ready file: {exc}")

    # threaded=True because every scan runs on its own thread while the UI
    # polls progress. The reloader and debugger stay off: this runs as a
    # sidecar, and a debugger would be a remote-code-execution surface.
    flask_app.run(
        host='127.0.0.1',
        port=port,
        debug=False,
        threaded=True,
        use_reloader=False,
    )


if __name__ == '__main__':
    main()
