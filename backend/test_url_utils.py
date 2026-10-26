"""
Tests for the shared URL helpers.

Regression: the scanners used to build probe URLs with an f-string like
f"{base_url}?{param}=1", which produces a malformed URL when the base already
has a query string. Scanning "http://host/search?q=test" requested
"http://host/search?q=test?search=1", where the second "?" became part of a
parameter value, so the payload never reached the application and the test
silently reported nothing.

Run with:  python test_url_utils.py
"""

import unittest
from urllib.parse import urlparse, parse_qs

from scanner_modules.url_utils import with_param, base_without_query, payload_url


def params_of(url):
    return parse_qs(urlparse(url).query)


class WithParamTests(unittest.TestCase):
    def test_adds_query_when_none_exists(self):
        self.assertEqual(with_param("http://h/p", "q", "1"), "http://h/p?q=1")

    def test_appends_with_ampersand_when_query_exists(self):
        self.assertEqual(with_param("http://h/p?a=1", "q", "1"),
                         "http://h/p?a=1&q=1")

    def test_never_produces_a_double_question_mark(self):
        """The bug this module exists to fix."""
        for base in ("http://h/p", "http://h/p?a=1", "http://h/p?a=1&b=2"):
            out = with_param(base, "probe", "1")
            self.assertNotIn("??", out)
            self.assertEqual(out.count("?"), 1, out)

    def test_existing_value_is_replaced_not_duplicated(self):
        """A probe must sit in front of the real value, not behind it."""
        out = with_param("http://h/p?q=real", "q", "payload")
        self.assertEqual(params_of(out), {"q": ["payload"]})

    def test_other_parameters_are_preserved(self):
        out = with_param("http://h/p?a=1&b=2", "q", "1")
        self.assertEqual(params_of(out), {"a": ["1"], "b": ["2"], "q": ["1"]})

    def test_replace_false_keeps_both(self):
        out = with_param("http://h/p?q=old", "q", "new", replace=False)
        self.assertEqual(params_of(out)["q"], ["old", "new"])

    def test_payload_with_ampersand_is_encoded(self):
        out = with_param("http://h/p?a=1", "q", "x&y=z")
        self.assertEqual(params_of(out)["q"], ["x&y=z"])
        self.assertNotIn("&y=", out)

    def test_payload_with_hash_is_encoded(self):
        out = with_param("http://h/p", "q", "a#b")
        self.assertEqual(params_of(out)["q"], ["a#b"])

    def test_payload_with_space_and_quote(self):
        out = with_param("http://h/p", "q", "' OR 1=1 --")
        self.assertEqual(params_of(out)["q"], ["' OR 1=1 --"])

    def test_empty_path_gets_a_slash(self):
        self.assertIn("/", with_param("http://h", "q", "1"))

    def test_empty_url_is_returned_unchanged(self):
        self.assertEqual(with_param("", "q", "1"), "")
        self.assertEqual(with_param(None, "q", "1"), None)

    def test_scheme_and_host_are_untouched(self):
        out = with_param("https://Example.COM:8443/p?a=1", "q", "1")
        self.assertTrue(out.startswith("https://Example.COM:8443/p?"))

    def test_port_is_kept(self):
        out = with_param("http://127.0.0.1:8878/s?q=test", "search", "1")
        self.assertTrue(out.startswith("http://127.0.0.1:8878/s?"))

    def test_fragment_is_preserved(self):
        self.assertIn("#frag", with_param("http://h/p#frag", "q", "1"))


class BaseWithoutQueryTests(unittest.TestCase):
    def test_query_removed(self):
        self.assertEqual(base_without_query("http://h/p?a=1&b=2"), "http://h/p")

    def test_no_query_is_fine(self):
        self.assertEqual(base_without_query("http://h/p"), "http://h/p")

    def test_empty_is_fine(self):
        self.assertEqual(base_without_query(""), "")


class PayloadUrlTests(unittest.TestCase):
    def test_behaves_like_with_param(self):
        self.assertEqual(payload_url("http://h/p?a=1", "q", "1"),
                         with_param("http://h/p?a=1", "q", "1"))


class ScannerIntegrationTests(unittest.TestCase):
    """The scanners must no longer build URLs with a raw '?'."""

    MODULES = [
        "command_injection", "deserialization_scanner", "firewall_detector",
        "fuzzer", "idor_scanner", "lfi_scanner", "open_redirect_scanner",
        "sql_injection", "ssrf_scanner", "ssti_scanner", "xss_scanner",
        "xxe_scanner",
    ]

    def test_no_module_builds_a_raw_question_mark_url(self):
        import os
        here = os.path.dirname(os.path.abspath(__file__))
        offenders = []
        for name in self.MODULES:
            path = os.path.join(here, "scanner_modules", f"{name}.py")
            with open(path, encoding="utf-8") as fh:
                for number, line in enumerate(fh, 1):
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    # f"...}?{..." or f"...}?name=..." is the broken pattern
                    if ("}?" in stripped and "with_param" not in stripped
                            and '"""' not in stripped):
                        offenders.append(f"{name}.py:{number}: {stripped}")
        self.assertEqual(offenders, [],
                         "raw '?' URL building is back:\n  " + "\n  ".join(offenders))

    def test_every_fixed_module_imports_the_helper(self):
        import os
        here = os.path.dirname(os.path.abspath(__file__))
        missing = []
        for name in self.MODULES:
            path = os.path.join(here, "scanner_modules", f"{name}.py")
            with open(path, encoding="utf-8") as fh:
                if "from scanner_modules.url_utils import with_param" not in fh.read():
                    missing.append(name)
        self.assertEqual(missing, [], f"missing import: {missing}")


if __name__ == "__main__":
    unittest.main(verbosity=2)