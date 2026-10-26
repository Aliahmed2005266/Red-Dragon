"""
Intruder Module - Burp Suite-like automated payload injection tool

Supports three attack types:
  • Sniper       – one parameter, one payload set
  • Cluster Bomb – multiple parameters, cross-product of payload sets
  • Pitchfork    – multiple parameters, parallel payload sets (zip)
"""

import requests
import threading
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
import uuid


class Intruder:
    """Automated payload injection engine with multiple attack types and match conditions."""

    ATTACK_TYPES = {
        "sniper": "Sniper – one payload set into a single parameter",
        "cluster_bomb": "Cluster Bomb – cross-product across multiple parameters",
        "pitchfork": "Pitchfork – parallel payloads across multiple parameters",
    }

    MATCH_TYPES = {
        "contains": "Contains",
        "not_contains": "Does not contain",
        "status": "Status code",
        "length": "Length equals",
        "length_gt": "Length greater than",
        "regex": "Regex match",
    }

    # Built-in payload lists (Burp Suite style payload presets)
    PAYLOAD_PRESETS = {
        "usernames": {
            "label": "Common Usernames",
            "items": [
                "admin", "administrator", "root", "user", "test", "guest",
                "info", "support", "operator", "sysadmin", "manager", "sa",
                "demo", "backup", "oracle", "postgres", "ubuntu", "dev",
            ],
        },
        "passwords": {
            "label": "Common Passwords",
            "items": [
                "password", "123456", "12345678", "qwerty", "abc123",
                "password1", "admin", "letmein", "welcome", "monkey",
                "dragon", "master", "login", "football", "iloveyou",
                "admin123", "root", "toor", "pass123", "changeme",
                "P@ssw0rd", "test123", "guest", "welcome1", "passw0rd",
            ],
        },
        "numbers_0_99": {"label": "Numbers 0-99", "items": [str(i) for i in range(100)]},
        "years": {"label": "Years 1990-2025", "items": [str(y) for y in range(1990, 2026)]},
        "special_chars": {
            "label": "Special Characters",
            "items": list("!@#$%^&*()-_=+[]{};:,.<>/?|`~"),
        },
    }

    def __init__(self, target_url=None, session=None, payloads=None,
                 parameters=None, attack_type="sniper",
                 match_type="contains", match_value="",
                 method="GET", headers=None, body=None,
                 max_threads=20):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.payloads = payloads or [[""]]
        self.parameters = parameters or [{"name": "id", "position": "query"}]
        self.attack_type = attack_type
        self.match_type = match_type
        self.match_value = match_value
        self.method = method
        self.headers = headers or {}
        self.body = body
        self.max_threads = max_threads

        self.results = []
        self.findings = []
        self.is_running = False
        self.stop_flag = False
        self.attack_id = str(uuid.uuid4())
        self.started_at = None
        self.completed_at = None

    # ------------------------------------------------------------------ #
    # Payload combination generation
    # ------------------------------------------------------------------ #
    def _generate_payload_combinations(self):
        """Return a list of payload tuples based on the attack type."""
        if self.attack_type == "sniper":
            return [(p,) for p in self.payloads[0]]

        if self.attack_type == "cluster_bomb":
            from itertools import product
            return [combo for combo in product(*self.payloads)]

        if self.attack_type == "pitchfork":
            # zip the payload sets (parallel)
            return list(zip(*self.payloads))

        # Default to sniper behaviour
        return [(p,) for p in self.payloads[0]]

    # ------------------------------------------------------------------ #
    # Match-condition checking
    # ------------------------------------------------------------------ #
    def _check_match(self, response, match_type=None, match_value=None):
        """Return True when *response* satisfies the match condition."""
        mt = match_type or self.match_type
        mv = match_value or self.match_value

        text = response.text or ""

        if mt == "contains":
            return mv in text
        if mt == "not_contains":
            return mv not in text
        if mt == "status":
            try:
                return response.status_code == int(mv)
            except (ValueError, TypeError):
                return False
        if mt == "length":
            try:
                return len(text) == int(mv)
            except (ValueError, TypeError):
                return False
        if mt == "length_gt":
            try:
                return len(text) > int(mv)
            except (ValueError, TypeError):
                return False
        if mt == "regex":
            try:
                return bool(re.search(mv, text))
            except re.error:
                return False
        return False

    # ------------------------------------------------------------------ #
    # Core attack logic
    # ------------------------------------------------------------------ #
    def _build_request(self, payload_tuple):
        """Build the URL, method, headers, and body for a single payload combination."""
        method = self.method.upper()
        headers = dict(self.headers)
        body = self.body

        # Parse the target URL
        parsed = urlparse(self.target_url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        # Inject payloads into parameters
        for i, param in enumerate(self.parameters):
            pname = param["name"]
            payload = payload_tuple[i] if i < len(payload_tuple) else ""
            ptype = param.get("position", "query")
            if ptype == "query":
                query_params[pname] = [payload]
            elif ptype == "body":
                if body is None:
                    body = ""
                if f"{pname}=" in body:
                    body = body.replace(f"{pname}=", f"{pname}={payload}")
                else:
                    body = f"{pname}={payload}" if not body else f"{body}&{pname}={payload}"

        # Rebuild URL
        new_query = urlencode(query_params, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        url = urlunparse(new_parsed)
        return method, url, headers, body

    def _send_payload(self, payload_tuple):
        """Send a single request with the given payload combination and return a result dict."""
        if self.stop_flag:
            return None

        method, url, headers, body = self._build_request(payload_tuple)
        req_headers = dict(self.session.headers)
        req_headers.update(headers)

        start = time.time()
        try:
            if method == "GET":
                resp = self.session.get(url, headers=req_headers, timeout=30, allow_redirects=False)
            elif method == "POST":
                resp = self.session.post(url, headers=req_headers, data=body, timeout=30, allow_redirects=False)
            elif method == "PUT":
                resp = self.session.put(url, headers=req_headers, data=body, timeout=30, allow_redirects=False)
            elif method == "DELETE":
                resp = self.session.delete(url, headers=req_headers, timeout=30, allow_redirects=False)
            else:
                resp = self.session.request(method, url, headers=req_headers, data=body, timeout=30, allow_redirects=False)

            elapsed = time.time() - start
            matched = self._check_match(resp) if self.match_type != "none" else False

            result = {
                "payload": " | ".join(str(p) for p in payload_tuple),
                "method": method,
                "url": url,
                "status_code": resp.status_code,
                "response_length": len(resp.text),
                "time": f"{elapsed:.3f}s",
                "matched": matched,
                "response_snippet": resp.text[:500] if resp.text else "",
                "headers": dict(resp.headers),
            }

            if matched:
                self.findings.append({
                    "type": "Intruder",
                    "severity": "High",
                    "title": f"Payload matched condition: {payload_tuple}",
                    "description": (
                        f"Payload '{payload_tuple}' against parameter(s) "
                        f"[{', '.join(p['name'] for p in self.parameters)}] "
                        f"matched condition: {self.match_type} '{self.match_value}'"
                    ),
                    "url": url,
                    "payload": str(payload_tuple),
                    "status_code": resp.status_code,
                    "response_snippet": resp.text[:500],
                    "remediation": "Review parameter handling and implement proper input validation.",
                })

            return result

        except requests.exceptions.Timeout:
            return {
                "payload": " | ".join(str(p) for p in payload_tuple),
                "method": method, "url": url, "status_code": 0,
                "response_length": 0, "time": f"{time.time() - start:.3f}s",
                "matched": False, "response_snippet": "Request timed out", "error": "Timeout",
            }
        except Exception as e:
            return {
                "payload": " | ".join(str(p) for p in payload_tuple),
                "method": method, "url": url, "status_code": 0,
                "response_length": 0, "time": f"{time.time() - start:.3f}s",
                "matched": False, "response_snippet": str(e), "error": str(e),
            }

    # ------------------------------------------------------------------ #
    # Attack execution / control
    # ------------------------------------------------------------------ #
    def run_attack(self):
        """Execute the attack across all payload combinations using a thread pool."""
        self.is_running = True
        self.stop_flag = False
        self.started_at = time.time()
        self.results = []
        self.findings = []
        self._total = len(self._generate_payload_combinations())

        combinations = self._generate_payload_combinations()

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._send_payload, combo): combo for combo in combinations}
            for future in as_completed(futures):
                if self.stop_flag:
                    break
                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                except Exception:
                    pass

        self.completed_at = time.time()
        self.is_running = False
        return self.results

    def start_async(self):
        """Run the attack in a background thread."""
        thread = threading.Thread(target=self.run_attack, daemon=True)
        thread.start()
        return thread

    def stop(self):
        """Signal the running attack to stop."""
        self.stop_flag = True
        return True

    def get_status(self):
        """Return current attack status and results."""
        if getattr(self, "_total", None) is None:
            self._total = len(self._generate_payload_combinations())
        return {
            "attack_id": self.attack_id,
            "attack_type": self.attack_type,
            "target": self.target_url,
            "is_running": self.is_running,
            "stopped": self.stop_flag,
            "total_requests": self._total,
            "completed": len(self.results),
            "matched": sum(1 for r in self.results if r.get("matched")),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "results": self.results,
            "findings": self.findings,
        }
