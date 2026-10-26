"""
Tests for the AI security agent.

Focuses on the guarantees that matter: the API key is never exposed, the
attack plan is gated on authorisation, scan context is actually included in
the prompt, and the session endpoints behave correctly.

Run with:  python test_ai_agent.py
"""

import unittest
from unittest import mock

import server
from scanner_modules.ai_agent import normalize_model_name, MAX_MODEL_NAME_LENGTH
from scanner_modules.ai_security_agent import SecurityAgent

RESULTS = {
    "target": "https://shop.example.com",
    "domain": "shop.example.com",
    "ip_address": "93.184.216.34",
    "statistics": {"total_findings": 2, "critical": 1, "high": 1,
                   "medium": 0, "low": 0, "info": 0},
    "findings": [
        {"severity": "Critical", "type": "SQL Injection",
         "title": "SQLi in id parameter", "url": "https://shop/item?id=1",
         "parameter": "id"},
        {"severity": "High", "type": "IDOR", "title": "IDOR on order",
         "url": "https://shop/order?id=9", "parameter": "id"},
    ],
    "architecture": {
        "architecture": {
            "servers": [{"name": "Nginx", "version": "1.24.0", "confidence": "high"}],
            "databases": [{"name": "MySQL", "version": None, "confidence": "high"}],
        },
        "summary": "Server: Nginx | Database: MySQL",
        "databases": ["MySQL"],
    },
    "parameters": [{"name": "id", "live": True}, {"name": "page", "live": True},
                   {"name": "redirect", "live": False}],
    "open_ports": [{"port": 80, "service": "http"}],
    "firewall": "Cloudflare",
}


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.agent = SecurityAgent()
        self.context = self.agent.build_context(RESULTS)

    def test_target_metadata_is_captured(self):
        self.assertEqual(self.context["target"], "https://shop.example.com")
        self.assertEqual(self.context["domain"], "shop.example.com")

    def test_statistics_are_summarised(self):
        stats = self.context["summary_statistics"]
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["critical"], 1)

    def test_findings_are_compacted_and_kept(self):
        self.assertEqual(len(self.context["findings"]), 2)
        self.assertIn("SQLi in id parameter",
                      [f["title"] for f in self.context["findings"]])

    def test_architecture_is_grouped(self):
        self.assertIn("servers", self.context["architecture"])
        self.assertEqual(self.context["architecture"]["servers"][0]["name"],
                         "Nginx")

    def test_live_parameters_are_separated(self):
        params = self.context["parameters"]
        self.assertIn("id", params["confirmed_live"])
        self.assertIn("redirect", params["seen_but_unconfirmed"])

    def test_empty_results_produce_empty_context(self):
        self.assertEqual(self.agent.build_context({}), {})
        self.assertEqual(self.agent.build_context(None), {})

    def test_prompt_contains_the_key_facts(self):
        text = self.agent._context_prompt(self.context)
        for expected in ("shop.example.com", "MySQL", "Nginx",
                         "SQLi in id parameter", "80", "Cloudflare"):
            self.assertIn(str(expected), text)

    def test_prompt_without_context_is_graceful(self):
        self.assertIn("No scan results",
                      self.agent._context_prompt({}))


class CustomModelNameTests(unittest.TestCase):
    """The user may name any model the provider accepts, not only presets."""

    def test_none_falls_back_to_the_default(self):
        self.assertIsNone(normalize_model_name(None))

    def test_blank_becomes_none(self):
        self.assertIsNone(normalize_model_name(""))
        self.assertIsNone(normalize_model_name("   "))

    def test_name_is_trimmed(self):
        self.assertEqual(normalize_model_name("  gpt-4o-mini  "),
                         "gpt-4o-mini")

    def test_non_string_is_rejected(self):
        for bad in (123, ["gpt-4"], {"model": "gpt-4"}):
            with self.assertRaises(ValueError):
                normalize_model_name(bad)

    def test_overlong_name_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_model_name("m" * (MAX_MODEL_NAME_LENGTH + 1))

    def test_any_name_not_in_the_preset_list_is_accepted(self):
        # The whole point: names beyond the hard-coded presets are valid.
        self.assertEqual(
            normalize_model_name("my-fine-tuned-llama-3.3-70b"),
            "my-fine-tuned-llama-3.3-70b")

    def test_set_provider_accepts_a_custom_model_name(self):
        agent = SecurityAgent()
        with mock.patch.object(SecurityAgent, "_create_client",
                               return_value=object()):
            result = agent.set_provider("openai", "sk-test",
                                        "my-fine-tuned-model")
        self.assertTrue(result["success"])
        self.assertEqual(result["model"], "my-fine-tuned-model")
        self.assertEqual(agent.model, "my-fine-tuned-model")

    def test_set_provider_rejects_a_malformed_model_name(self):
        agent = SecurityAgent()
        result = agent.set_provider("openai", "sk-test", 42)
        self.assertFalse(result["success"])
        self.assertIn("string", result["error"])
        # Nothing is configured when validation fails
        self.assertIsNone(agent.client)


class PromptTests(unittest.TestCase):
    def setUp(self):
        self.agent = SecurityAgent()
        # Give it a client so _run proceeds to the provider call
        self.agent.client = object()
        self.captured = []

    def _capture(self, reply="STUB"):
        captured = self.captured
        # Patched onto the class, so the first argument is the agent instance
        def fake_call(agent, messages):
            captured.append(messages)
            return {"reply": reply}
        return fake_call

    def test_ask_includes_scan_context(self):
        with mock.patch.object(SecurityAgent, "_call_provider", self._capture()):
            self.agent.ask("Is the SQLi exploitable?", RESULTS)
        prompt = self.captured[-1][-1]["content"]
        self.assertIn("SCAN DATA FOR CONTEXT", prompt)
        self.assertIn("SQLi in id parameter", prompt)

    def test_ask_without_results_says_so(self):
        with mock.patch.object(SecurityAgent, "_call_provider", self._capture()):
            self.agent.ask("What is SQLi?")
        prompt = self.captured[-1][-1]["content"]
        self.assertIn("No scan results are loaded", prompt)

    def test_ask_requires_a_question(self):
        self.assertIn("error", self.agent.ask("   "))

    def test_report_uses_audience_guidance(self):
        with mock.patch.object(SecurityAgent, "_call_provider", self._capture()):
            self.agent.generate_report(RESULTS, audience="executive")
        prompt = self.captured[-1][-1]["content"]
        self.assertIn("non-technical decision maker", prompt)
        self.assertIn("Remediation Plan", prompt)

    def test_attack_plan_requires_authorisation_prompt(self):
        with mock.patch.object(SecurityAgent, "_call_provider", self._capture()):
            self.agent.build_attack_plan(RESULTS)
        system = self.captured[-1][0]["content"]
        self.assertIn("authorised security testing", system)
        self.assertIn("destructive payloads", system)

    def test_attack_plan_carries_scope_notes(self):
        with mock.patch.object(SecurityAgent, "_call_provider", self._capture()):
            self.agent.build_attack_plan(RESULTS, scope_note="staging only")
        prompt = self.captured[-1][-1]["content"]
        self.assertIn("staging only", prompt)

    def test_history_accumulates(self):
        with mock.patch.object(SecurityAgent, "_call_provider", self._capture()):
            self.agent.ask("first", RESULTS)
            self.agent.ask("second", RESULTS)
        self.assertEqual(len(self.agent.conversation_history), 4)

    def test_unconfigured_agent_returns_error(self):
        unconfigured = SecurityAgent()
        self.assertIn("error", unconfigured.ask("hello", RESULTS))


class SessionEndpointTests(unittest.TestCase):
    def setUp(self):
        server.app.config["TESTING"] = True
        self.client = server.app.test_client()
        server.ai_sessions.clear()
        self.patches = [
            mock.patch.object(SecurityAgent, "_create_client", return_value=object()),
            mock.patch.object(SecurityAgent, "_call_provider",
                              return_value={"reply": "OK"}),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        server.ai_sessions.clear()

    def _create(self, key="sk-secret-abc", **extra):
        return self.client.post("/api/ai/session",
                                json={"provider": "openai",
                                      "api_key": key, **extra})

    def test_session_requires_provider_and_key(self):
        self.assertEqual(self.client.post("/api/ai/session", json={}).status_code, 400)
        self.assertEqual(self.client.post(
            "/api/ai/session", json={"provider": "openai"}).status_code, 400)

    def test_session_creation_verifies_key(self):
        data = self._create().get_json()
        self.assertTrue(data["verified"])
        self.assertTrue(data["session_id"])

    def test_api_key_is_never_returned(self):
        body = self._create().get_data(as_text=True)
        self.assertNotIn("sk-secret-abc", body)

    def test_describe_never_returns_the_key(self):
        sid = self._create().get_json()["session_id"]
        body = self.client.get(f"/api/ai/session/{sid}").get_data(as_text=True)
        self.assertNotIn("sk-secret-abc", body)

    def test_describe_reports_provider_and_model(self):
        sid = self._create().get_json()["session_id"]
        data = self.client.get(f"/api/ai/session/{sid}").get_json()
        self.assertTrue(data["configured"])
        self.assertEqual(data["provider"], "openai")

    def test_session_accepts_a_model_name_not_in_the_preset_list(self):
        response = self._create(model="  my-fine-tuned-model  ")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        # The custom name is kept (and trimmed), not replaced by a preset
        self.assertEqual(data["model"], "my-fine-tuned-model")
        sid = data["session_id"]
        described = self.client.get(f"/api/ai/session/{sid}").get_json()
        self.assertEqual(described["model"], "my-fine-tuned-model")

    def test_session_blank_model_falls_back_to_the_default(self):
        data = self._create(model="   ").get_json()
        default = server.ai_sessions[data["session_id"]]["agent"].model
        self.assertEqual(default, "gpt-4")

    def test_session_rejects_a_malformed_model_name(self):
        response = self._create(model=12345)
        self.assertEqual(response.status_code, 400)
        self.assertIn("string", response.get_json()["error"])

    def test_sessions_are_isolated(self):
        a = self._create("sk-key-one").get_json()["session_id"]
        b = self._create("sk-key-two").get_json()["session_id"]
        self.assertNotEqual(a, b)
        # Each session keeps its own agent and history
        self.assertIsNot(server.ai_sessions[a]["agent"],
                         server.ai_sessions[b]["agent"])

    def test_ask_requires_a_valid_session(self):
        self.assertEqual(self.client.post(
            "/api/ai/agent/ask",
            json={"session_id": "nope", "question": "hi"}).status_code, 404)

    def test_ask_requires_a_question(self):
        sid = self._create().get_json()["session_id"]
        self.assertEqual(self.client.post(
            "/api/ai/agent/ask", json={"session_id": sid}).status_code, 400)

    def test_ask_uses_server_side_scan_by_id(self):
        server.scan_results["scan_ctx"] = RESULTS
        sid = self._create().get_json()["session_id"]
        with mock.patch.object(SecurityAgent, "_call_provider",
                               return_value={"reply": "done"}):
            data = self.client.post("/api/ai/agent/ask", json={
                "session_id": sid, "scan_id": "scan_ctx",
                "question": "hi"}).get_json()
        self.assertTrue(data["used_scan_context"])
        server.scan_results.pop("scan_ctx", None)

    def test_report_works_from_a_session(self):
        sid = self._create().get_json()["session_id"]
        with mock.patch.object(SecurityAgent, "_call_provider",
                               return_value={"reply": "REPORT"}):
            data = self.client.post("/api/ai/agent/report", json={
                "session_id": sid, "scan_results": RESULTS}).get_json()
        self.assertEqual(data["reply"], "REPORT")

    def test_attack_plan_blocked_without_authorisation(self):
        sid = self._create().get_json()["session_id"]
        response = self.client.post("/api/ai/agent/attack-plan", json={
            "session_id": sid, "scan_results": RESULTS})
        self.assertEqual(response.status_code, 400)
        self.assertIn("permission", response.get_json()["error"])

    def test_attack_plan_allowed_with_authorisation(self):
        sid = self._create().get_json()["session_id"]
        with mock.patch.object(SecurityAgent, "_call_provider",
                               return_value={"reply": "PLAN"}):
            response = self.client.post("/api/ai/agent/attack-plan", json={
                "session_id": sid, "scan_results": RESULTS,
                "authorised": True})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["reply"], "PLAN")

    def test_delete_clears_the_key(self):
        sid = self._create().get_json()["session_id"]
        agent = server.ai_sessions[sid]["agent"]
        self.client.delete(f"/api/ai/session/{sid}")
        self.assertIsNone(agent.api_key)
        self.assertIsNone(agent.client)
        self.assertEqual(agent.conversation_history, [])
        self.assertNotIn(sid, server.ai_sessions)

    def test_delete_unknown_session(self):
        self.assertEqual(
            self.client.delete("/api/ai/session/nope").status_code, 404)

    def test_provider_error_is_surfaced(self):
        sid = self._create().get_json()["session_id"]
        with mock.patch.object(SecurityAgent, "_call_provider",
                               return_value={"error": "rate limited"}):
            response = self.client.post("/api/ai/agent/ask", json={
                "session_id": sid, "question": "hi",
                "scan_results": RESULTS})
        self.assertEqual(response.status_code, 502)
        self.assertIn("rate limited", response.get_json()["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)