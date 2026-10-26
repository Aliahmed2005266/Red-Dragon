"""
Tests for the installed desktop application.

Covers the launch-token guard (the protection that stops a web page from
driving the scanner), loopback-only binding, port selection, serving the
compiled UI with the token injected, path-traversal resistance, the settings
store, and route registration integrity.

Run with:  python test_desktop.py
"""

import json
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

import desktop
from config_store import DEFAULTS, get_store, get_store_path, remember_target, save_store

# Populated by setUpModule before any test runs
SHARED = {}


def make_ui_dir(base):
    """Build a tiny stand-in for the compiled React app."""
    ui = os.path.join(base, "ui")
    os.makedirs(ui, exist_ok=True)
    with open(os.path.join(ui, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(
            "<!DOCTYPE html><html><head><title>RD</title></head><body>"
            + desktop.BOOTSTRAP_TAG +
            '<script defer="defer" src="/static/js/main.test1234.js"></script>'
            "<div id=root></div></body></html>"
        )
    with open(os.path.join(ui, "static.txt"), "w", encoding="utf-8") as fh:
        fh.write("STATIC-OK")

    # The compiled interface loads its bundle from /static/js/. Flask's built-in
    # static rule used to shadow the catch-all and 404 these, which left the
    # window black, so the fixture mirrors the real layout.
    os.makedirs(os.path.join(ui, "static", "js"), exist_ok=True)
    with open(os.path.join(ui, "static", "js", "main.test1234.js"), "w",
              encoding="utf-8") as fh:
        fh.write("window.__BUNDLE_LOADED__=true;")
    os.makedirs(os.path.join(ui, "static", "css"), exist_ok=True)
    with open(os.path.join(ui, "static", "css", "main.test1234.css"), "w",
              encoding="utf-8") as fh:
        fh.write("body{}")
    return ui


def build_shared_server():
    """Build the app and start it once for the whole module.

    A throwaway Flask app is used here so the module-level server.app stays
    clean for the other test suites, which rely on it being untouched after
    other tests have already handled requests (route decorators and
    before_request hooks cannot be installed after the first request). The
    desktop test suite operates on this isolated app and will therefore never
    pollute the shared app used by every other test module.
    """
    tmp = tempfile.mkdtemp()
    ui = make_ui_dir(tmp)
    with open(os.path.join(tmp, "secret.txt"), "w", encoding="utf-8") as fh:
        fh.write("TOP-SECRET")

    desktop.find_ui_build = lambda: ui

    # Build a fresh Flask instance so the shared server.app is never mutated.
    # The guard (a WSGI middleware) and the UI routes are installed on this
    # copy, so other tests that drive server.app directly are unaffected.
    from server import Flask, app as server
    desktop_app = Flask(__name__)
    desktop_app.config['TESTING'] = True

    # Bring the module-level API routes over from the shared app so the
    # desktop test suite drives the same surface the real app exposes.
    # Skip the static endpoint: Flask's own /static rule already exists on the
    # isolated app and would be overwritten.
    for _rule in server.url_map.iter_rules():
        if _rule.endpoint == 'static':
            continue
        view = server.view_functions.get(_rule.endpoint)
        if view is not None:
            desktop_app.add_url_rule(_rule.rule, _rule.endpoint, view)

    # Register the extension endpoints (fuzzing, subdomains, mapping, AI, ...)
    # These are already present because we copied all routes from server.app
    # (which had register_extensions applied at import time).
    # register_extensions(desktop_app) would attempt to re-register the same
    # endpoints, raising an "overwriting existing endpoint" error.

    desktop.issue_token()
    desktop.install_guard(desktop_app)
    desktop.install_ui(desktop_app, ui)

    port = desktop.pick_free_port()
    threading.Thread(
        target=lambda: desktop_app.run(host="127.0.0.1", port=port, debug=False,
                                       threaded=True, use_reloader=False),
        daemon=True).start()
    time.sleep(0.8)
    return {"tmp": tmp, "ui": ui, "app": desktop_app, "port": port}


def setUpModule():
    global SHARED
    SHARED = build_shared_server()


def tearDownModule():
    shutil.rmtree(SHARED["tmp"], ignore_errors=True)


class TempUiTests(unittest.TestCase):
    """The launch-token guard and the UI the desktop backend serves."""

    def setUp(self):
        # The guard reads this on every request, so a fresh token per test works
        self.token = desktop.issue_token()
        self.port = SHARED["port"]

    def get(self, path, headers=None):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as res:
                return res.status, res.read().decode("utf-8", "ignore"), dict(res.headers)
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode("utf-8", "ignore"), dict(err.headers)

    def auth(self):
        return {"X-RD-Token": self.token}

    # --- token guard -----------------------------------------------------
    def test_api_requires_token(self):
        status, body, _ = self.get("/api/health")
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)["code"], "invalid_token")

    def test_api_rejects_wrong_token(self):
        status, _, _ = self.get("/api/health", {"X-RD-Token": "nope"})
        self.assertEqual(status, 403)

    def test_api_rejects_empty_token(self):
        status, _, _ = self.get("/api/health", {"X-RD-Token": ""})
        self.assertEqual(status, 403)

    def test_api_accepts_valid_token(self):
        status, body, _ = self.get("/api/health", self.auth())
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "healthy")

    def test_scan_endpoint_requires_token(self):
        """The dangerous endpoint must be guarded, not just health."""
        status, _, _ = self.get("/api/scan/modules")
        self.assertEqual(status, 403)
        status, _, _ = self.get("/api/scan/modules", self.auth())
        self.assertEqual(status, 200)

    def test_previous_token_stops_working(self):
        """A token from a previous request must not be replayable."""
        old = self.token
        desktop.issue_token()
        status, _, _ = self.get("/api/health", {"X-RD-Token": old})
        self.assertEqual(status, 403)

    # --- UI serving ------------------------------------------------------
    def test_index_is_served(self):
        status, body, headers = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertIn("id=root", body)

    def test_token_injected_and_placeholder_replaced(self):
        _, body, _ = self.get("/")
        self.assertIn("window.__RED_DRAGON__", body)
        self.assertIn(self.token, body)
        self.assertNotIn(desktop.INDEX_PLACEHOLDER, body)

    def test_injected_token_is_valid_json(self):
        """A token with quotes must not be able to break out of the script."""
        raw = desktop._inject_bootstrap("x" + desktop.INDEX_PLACEHOLDER, 'a"b\\c', "/ui")
        start = raw.index("window.__RED_DRAGON__=") + len("window.__RED_DRAGON__=")
        end = raw.index(";</script>", start)
        self.assertEqual(json.loads(raw[start:end])["token"], 'a"b\\c')

    def test_static_asset_served(self):
        status, body, _ = self.get("/static.txt")
        self.assertEqual(status, 200)
        self.assertEqual(body, "STATIC-OK")

    # --- the bundle the window actually needs ---------------------------
    def test_js_bundle_is_served(self):
        """Regression: the window rendered black because this 404'd.

        Flask's built-in /static/<path> rule pointed at a folder that does not
        exist and shadowed the catch-all that serves the interface, so the
        compiled bundle never loaded and the window stayed black.
        """
        status, body, _ = self.get("/static/js/main.test1234.js")
        self.assertEqual(status, 200)
        self.assertIn("__BUNDLE_LOADED__", body)

    def test_css_bundle_is_served(self):
        status, _, _ = self.get("/static/css/main.test1234.css")
        self.assertEqual(status, 200)

    def test_flask_static_rule_points_at_the_interface(self):
        """Flask's /static rule shadows the catch-all, so it must be aimed at
        the interface build or the bundle 404s and the window goes black."""
        self.assertEqual(
            os.path.normcase(SHARED["app"].static_folder or ""),
            os.path.normcase(os.path.join(SHARED["ui"], "static")))

    def test_index_references_a_bundle_we_can_serve(self):
        """The served page must not reference a bundle that 404s."""
        _, page, _ = self.get("/")
        import re
        for src in re.findall(r'src="(/static/[^"]+)"', page):
            status, _, _ = self.get(src)
            self.assertEqual(status, 200, f"{src} returned {status}")

    def test_missing_asset_404s_rather_than_serving_index(self):
        status, body, _ = self.get("/static/js/nope.js")
        self.assertEqual(status, 404)
        self.assertNotIn("__RED_DRAGON__", body)

    def test_spa_fallback_serves_index(self):
        status, body, _ = self.get("/deep/client/route")
        self.assertEqual(status, 200)
        self.assertIn("window.__RED_DRAGON__", body)

    def test_index_not_cached(self):
        _, _, headers = self.get("/")
        self.assertIn("no-store", headers.get("Cache-Control", ""))

    def test_unknown_api_path_is_404(self):
        status, _, _ = self.get("/api/definitely/not/here", self.auth())
        self.assertEqual(status, 404)

    # --- path traversal --------------------------------------------------
    def test_traversal_blocked(self):
        for attempt in ("/../secret.txt", "/%2e%2e/secret.txt", "/..%2fsecret.txt"):
            _, body, _ = self.get(attempt)
            self.assertNotIn("TOP-SECRET", body, f"leaked via {attempt}")

    def test_traversal_deep_blocked(self):
        _, body, _ = self.get("/../../etc/passwd")
        self.assertNotIn("root:", body)
class PortTests(unittest.TestCase):
    def test_pick_free_port_returns_bindable_port(self):
        port = desktop.pick_free_port()
        self.assertIsInstance(port, int)
        self.assertGreater(port, 0)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(('127.0.0.1', port))

    def test_two_calls_differ(self):
        """A fixed port would collide when two copies of the app run."""
        self.assertNotEqual(desktop.pick_free_port(), desktop.pick_free_port())

    def test_occupied_port_falls_back(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(('127.0.0.1', 0))
            sock.listen(1)
            busy = sock.getsockname()[1]
            # Must not raise, and must not hand back the taken port
            self.assertNotEqual(desktop.pick_free_port(busy), busy)


class TokenTests(unittest.TestCase):
    def setUp(self):
        self.token = desktop.issue_token()

    def test_token_is_long_and_random(self):
        self.assertGreaterEqual(len(self.token), 32)
        self.assertNotEqual(self.token, desktop.issue_token())

    def test_valid_token_accepted(self):
        self.assertTrue(desktop._token_is_valid(self.token))

    def test_invalid_tokens_rejected(self):
        for bad in ('', None, 'x', self.token[:-1], self.token + 'x'):
            self.assertFalse(desktop._token_is_valid(bad), f'accepted {bad!r}')

    def test_no_token_issued_means_nothing_valid(self):
        original = desktop.APP_TOKEN
        try:
            desktop.APP_TOKEN = None
            self.assertFalse(desktop._token_is_valid('anything'))
        finally:
            desktop.APP_TOKEN = original

class RouteIntegrityTests(unittest.TestCase):
    """Guards against the duplicate-route bug that silently dropped endpoints."""

    def test_no_duplicate_view_functions(self):
        import server
        names = list(server.app.view_functions.keys())
        # Flask stores one entry per endpoint name, so a re-registration would
        # have raised long before this. Assert the real symptom instead:
        # the routes the UI depends on must all exist.
        for route in ("/api/fuzz", "/api/encode", "/api/decode",
                      "/api/intruder/start", "/api/repeater/send",
                      "/api/proxy/toggle", "/api/scan/deep",
                      "/api/network/start", "/api/ai/clear",
                      "/api/ai/remediation", "/api/app/info"):
            self.assertIn(route, [str(r) for r in server.app.url_map.iter_rules()],
                          f"{route} is missing")

    def test_ai_routes_registered(self):
        import server
        routes = {str(r) for r in server.app.url_map.iter_rules()}
        for route in ("/api/ai/configure", "/api/ai/chat", "/api/ai/analyze"):
            self.assertIn(route, routes)


class SettingsStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig = os.environ.get("RED_DRAGON_CONFIG_DIR")
        os.environ["RED_DRAGON_CONFIG_DIR"] = self.tmp

    def tearDown(self):
        if self._orig is None:
            os.environ.pop("RED_DRAGON_CONFIG_DIR", None)
        else:
            os.environ["RED_DRAGON_CONFIG_DIR"] = self._orig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_defaults_when_missing(self):
        data = get_store()
        self.assertEqual(data["authorized"], False)
        self.assertEqual(data["targets"], [])

    def test_save_and_reload(self):
        data = get_store()
        data["authorized"] = True
        data["ai_provider"] = "openai"
        ok, _ = save_store(data)
        self.assertTrue(ok)
        reloaded = get_store()
        self.assertTrue(reloaded["authorized"])
        self.assertEqual(reloaded["ai_provider"], "openai")

    def test_corrupt_file_falls_back_to_defaults(self):
        with open(get_store_path(), "w", encoding="utf-8") as fh:
            fh.write("{not json at all")
        self.assertEqual(get_store()["authorized"], False)

    def test_unknown_keys_are_dropped(self):
        save_store({**get_store(), "evil": "payload", "authorized": True})
        self.assertNotIn("evil", get_store())

    def test_api_keys_are_never_stored(self):
        """The schema has no key field, so a key cannot be persisted."""
        data = get_store()
        data["api_key"] = "sk-should-not-persist"
        save_store(data)
        self.assertNotIn("api_key", get_store())

    def test_remember_target_dedupes(self):
        remember_target("https://a.test")
        remember_target("https://b.test")
        remember_target("https://a.test")
        targets = get_store()["targets"]
        self.assertEqual(targets, ["https://a.test", "https://b.test"])

    def test_remember_target_sets_last_scan(self):
        remember_target("https://c.test")
        data = get_store()
        self.assertEqual(data["last_scan_target"], "https://c.test")
        self.assertEqual(data["default_target"], "https://c.test")

    def test_remember_blank_is_ignored(self):
        remember_target("   ")
        self.assertEqual(get_store()["targets"], [])

    def test_save_creates_directory(self):
        nested = os.path.join(self.tmp, "a", "b")
        os.environ["RED_DRAGON_CONFIG_DIR"] = nested
        ok, _ = save_store(get_store())
        self.assertTrue(ok)
        self.assertTrue(os.path.isfile(os.path.join(nested, "settings.json")))


class AppEndpointTests(unittest.TestCase):
    """The /api/app endpoints used by the desktop shell."""

    def setUp(self):
        import server
        server.app.config["TESTING"] = True
        self.client = server.app.test_client()
        self.h = {"X-RD-Token": desktop.issue_token()}

    def test_info_reports_app(self):
        res = self.client.get("/api/app/info", headers=self.h)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["name"], "Red Dragon")
        self.assertTrue(data["version"])

    def test_info_never_leaks_token(self):
        res = self.client.get("/api/app/info", headers=self.h)
        body = json.dumps(res.get_json())
        self.assertNotIn(self.h["X-RD-Token"], body)
        self.assertNotIn("token", body.lower())

    def test_settings_round_trip(self):
        tmp = tempfile.mkdtemp()
        orig = os.environ.get("RED_DRAGON_CONFIG_DIR")
        os.environ["RED_DRAGON_CONFIG_DIR"] = tmp
        try:
            res = self.client.post("/api/app/settings",
                                   json={"authorized": True}, headers=self.h)
            self.assertEqual(res.status_code, 200)
            self.assertTrue(res.get_json()["settings"]["authorized"])
            res = self.client.get("/api/app/settings", headers=self.h)
            self.assertTrue(res.get_json()["settings"]["authorized"])
        finally:
            if orig is None:
                os.environ.pop("RED_DRAGON_CONFIG_DIR", None)
            else:
                os.environ["RED_DRAGON_CONFIG_DIR"] = orig
            shutil.rmtree(tmp, ignore_errors=True)

    def test_settings_ignores_unknown_keys(self):
        tmp = tempfile.mkdtemp()
        orig = os.environ.get("RED_DRAGON_CONFIG_DIR")
        os.environ["RED_DRAGON_CONFIG_DIR"] = tmp
        try:
            self.client.post("/api/app/settings",
                             json={"evil": "x", "theme": "light"}, headers=self.h)
            saved = get_store()
            self.assertNotIn("evil", saved)
            self.assertEqual(saved["theme"], "light")
        finally:
            if orig is None:
                os.environ.pop("RED_DRAGON_CONFIG_DIR", None)
            else:
                os.environ["RED_DRAGON_CONFIG_DIR"] = orig
            shutil.rmtree(tmp, ignore_errors=True)

    def test_remember_target_endpoint(self):
        tmp = tempfile.mkdtemp()
        orig = os.environ.get("RED_DRAGON_CONFIG_DIR")
        os.environ["RED_DRAGON_CONFIG_DIR"] = tmp
        try:
            res = self.client.post("/api/app/remember-target",
                                   json={"target_url": "https://x.test"}, headers=self.h)
            self.assertEqual(res.status_code, 200)
            self.assertIn("https://x.test", res.get_json()["settings"]["targets"])
        finally:
            if orig is None:
                os.environ.pop("RED_DRAGON_CONFIG_DIR", None)
            else:
                os.environ["RED_DRAGON_CONFIG_DIR"] = orig
            shutil.rmtree(tmp, ignore_errors=True)



class MinifiedBuildTests(unittest.TestCase):
    """The token must survive the production HTML build.

    Regression: the placeholder was an HTML comment, and the production
    minifier strips comments. The packaged app then served a page with no
    token and every API call returned 403, while the dev build worked fine.
    """

    BUILD_INDEX = "index.html"

    def test_placeholder_survives_in_source_template(self):
        path = os.path.join(os.path.dirname(__file__), "..",
                            "frontend", "public", "index.html")
        if not os.path.isfile(path):
            self.skipTest("frontend template not present")
        with open(path, encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn(desktop.BOOTSTRAP_TAG, html)
        # A bare comment placeholder would be stripped by the minifier
        self.assertNotIn("<!--RED_DRAGON_BOOTSTRAP-->", html)

    def test_injection_works_without_any_placeholder(self):
        """Even a minified page with the tag removed still gets a token."""
        minified = ('<!doctype html><html><head><title>t</title>'
                    '</head><body><div id=root></div></body></html>')
        out = desktop._inject_bootstrap(minified, "TOKEN123", "/ui")
        self.assertIn("TOKEN123", out)
        self.assertIn("window.__RED_DRAGON__", out)
        # Must land inside head so it runs before the app bundle
        self.assertLess(out.index("TOKEN123"), out.index("</head>"))

    def test_injection_handles_no_html_structure(self):
        out = desktop._inject_bootstrap("just text", "TOKEN123", "/ui")
        self.assertIn("TOKEN123", out)

    def test_injection_keeps_single_bootstrap_tag(self):
        page = ('<html><head>' + desktop.BOOTSTRAP_TAG + '</head>'
                '<body><div id=root></div></body></html>')
        out = desktop._inject_bootstrap(page, "TOKEN123", "/ui")
        self.assertEqual(out.count("red-dragon-bootstrap"), 1)
        self.assertIn("TOKEN123", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
