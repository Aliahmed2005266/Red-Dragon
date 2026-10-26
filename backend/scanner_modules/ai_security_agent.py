"""
AI Security Agent

A session-scoped AI assistant that reasons over Red Dragon scan results and
can:

  * answer questions about a target using the full scan context
  * generate a professional security report
  * build an attack / test plan for the findings

Design notes:
  * One instance per session, so a user's API key and conversation history are
    never shared with another user. The older module-level `ai_agent` singleton
    leaks both across every request that hits the process.
  * The API key is only ever held in memory for the life of the session and is
    never returned by any endpoint.
  * The "attack plan" mode is explicitly scoped to authorised testing. It
    produces a plan and verification steps for someone who already has
    permission to test the target; it is not an autonomous exploitation tool.
"""

import json
import uuid
from datetime import datetime

from scanner_modules.ai_agent import MultiProviderAIAgent

# How much of the scan to include in a prompt. Keeps requests within budget
# and avoids token-limit failures on large scans.
MAX_FINDINGS_IN_PROMPT = 60
MAX_HISTORY_MESSAGES = 12


class SecurityAgent(MultiProviderAIAgent):
    """AI agent with full access to a target's scan results."""

    def __init__(self, provider=None, api_key=None, model=None):
        super().__init__()
        # Reports and plans need more room than a chat turn
        self.max_tokens = 4000
        self.temperature = 0.4
        self.session_id = uuid.uuid4().hex
        self.created_at = datetime.now().isoformat()
        self.last_used = datetime.now().isoformat()
        if provider and api_key:
            self.set_provider(provider, api_key, model)

    # ------------------------------------------------------------------
    # Context building
    # ------------------------------------------------------------------

    def build_context(self, scan_results):
        """Turn scan results into a compact, structured brief for the model.

        Includes the technology fingerprint and discovered parameters, since
        those change which attack surfaces are worth testing.
        """
        if not scan_results:
            return {}

        stats = scan_results.get('statistics', {}) or {}
        findings = scan_results.get('findings', []) or []

        by_severity = {}
        for finding in findings:
            severity = finding.get('severity', 'Info')
            by_severity.setdefault(severity, 0)
            by_severity[severity] += 1

        # Compact the findings: keep what an analyst needs, drop verbose fields
        compact = []
        for finding in findings[:MAX_FINDINGS_IN_PROMPT]:
            compact.append({
                'severity': finding.get('severity', 'Info'),
                'type': finding.get('type', ''),
                'title': finding.get('title', '')[:160],
                'url': finding.get('url', ''),
                'parameter': finding.get('parameter', ''),
            })

        # Technology fingerprint, grouped by category
        architecture = {}
        fingerprint = scan_results.get('architecture') or {}
        for category, items in (fingerprint.get('architecture') or {}).items():
            if items:
                architecture[category] = [
                    {'name': i.get('name'), 'version': i.get('version'),
                     'confidence': i.get('confidence')}
                    for i in items
                ]

        # Discovered parameters, split by whether they were confirmed live
        parameters = scan_results.get('parameters') or []
        live_params = [p for p in parameters if p.get('live')]
        dead_params = [p for p in parameters if not p.get('live')]

        open_ports = scan_results.get('open_ports') or []
        if isinstance(open_ports, dict):
            open_ports = [open_ports]
        port_summary = []
        for port in open_ports[:20]:
            if isinstance(port, dict):
                port_summary.append({
                    'port': port.get('port'),
                    'service': port.get('service', port.get('state', '')),
                    'version': port.get('version', ''),
                })

        return {
            'target': scan_results.get('target', 'unknown'),
            'domain': scan_results.get('domain', ''),
            'ip': scan_results.get('ip_address', ''),
            'summary_statistics': {
                'total': stats.get('total_findings', len(findings)),
                'critical': stats.get('critical', 0),
                'high': stats.get('high', 0),
                'medium': stats.get('medium', 0),
                'low': stats.get('low', 0),
                'info': stats.get('info', 0),
            },
            'findings_by_severity': by_severity,
            'findings': compact,
            'findings_truncated': max(0, len(findings) - MAX_FINDINGS_IN_PROMPT),
            'architecture': architecture,
            'architecture_summary': fingerprint.get('summary', ''),
            'databases': fingerprint.get('databases', []),
            'parameters': {
                'total': len(parameters),
                'confirmed_live': [p.get('name') for p in live_params][:30],
                'seen_but_unconfirmed': [p.get('name') for p in dead_params][:30],
            },
            'open_ports': port_summary,
            'firewall': scan_results.get('firewall'),
            'rate_limits_tested': bool(scan_results.get('rate_limits')),
            'modules_run': scan_results.get('modules_run', []),
        }

    # ------------------------------------------------------------------
    # Prompting helpers
    # ------------------------------------------------------------------

    BASE_SYSTEM_PROMPT = (
        "You are a senior penetration tester and security consultant embedded in "
        "Red Dragon, a web vulnerability scanner. You are given the complete scan "
        "results for a target.\n"
        "Be concrete and technical: reference the actual finding titles, parameters "
        "and technologies from the data rather than giving generic advice. Cite the "
        "evidence you are reasoning from. If the data does not support a claim, say "
        "so instead of inventing it."
    )

    def _context_prompt(self, context):
        """Render the scan context as a readable briefing block."""
        if not context:
            return "No scan results are available yet for this target."

        stats = context.get('summary_statistics', {})
        lines = [
            f"Target: {context.get('target')}",
            f"Domain: {context.get('domain')}  IP: {context.get('ip')}",
            f"Findings: {stats.get('total', 0)} total "
            f"(critical {stats.get('critical', 0)}, high {stats.get('high', 0)}, "
            f"medium {stats.get('medium', 0)}, low {stats.get('low', 0)})",
        ]

        if context.get('architecture_summary'):
            lines.append(f"Stack: {context['architecture_summary']}")
        elif context.get('architecture'):
            parts = []
            for category, items in context['architecture'].items():
                names = ', '.join(
                    f"{i['name']}{' ' + i['version'] if i.get('version') else ''}"
                    for i in items if i.get('name')
                )
                if names:
                    parts.append(f"{category}: {names}")
            if parts:
                lines.append("Stack: " + " | ".join(parts))

        params = context.get('parameters') or {}
        if params.get('total'):
            live = params.get('confirmed_live') or []
            unconfirmed = params.get('seen_but_unconfirmed') or []
            detail = f"Parameters found: {params['total']}"
            if live:
                detail += f" (confirmed handled by the app: {', '.join(live)})"
            if unconfirmed:
                detail += f" (seen in markup but not confirmed live: {', '.join(unconfirmed)})"
            lines.append(detail)

        if context.get('open_ports'):
            ports = ', '.join(
                f"{p.get('port')}{'/' + p.get('service') if p.get('service') else ''}"
                for p in context['open_ports'][:10]
            )
            lines.append(f"Open ports: {ports}")

        if context.get('firewall'):
            lines.append(f"WAF/firewall: {context['firewall']}")

        if context.get('findings'):
            lines.append("")
            lines.append("Findings:")
            for finding in context['findings']:
                param = f" [param: {finding['parameter']}]" if finding.get('parameter') else ''
                lines.append(
                    f"- [{finding['severity']}] {finding['type']}: "
                    f"{finding['title']}{param} @ {finding.get('url', '')}"
                )
            if context.get('findings_truncated'):
                lines.append(
                    f"... and {context['findings_truncated']} more findings not shown."
                )

        return "\n".join(lines)

    def _run(self, user_prompt, system_extra=''):
        """Send a prompt to the provider and return the reply."""
        if not self.client:
            return {'error': 'No AI provider configured. Supply a provider and API key.'}

        system = self.BASE_SYSTEM_PROMPT
        if system_extra:
            system += "\n\n" + system_extra

        messages = [{'role': 'system', 'content': system}]
        for message in self.conversation_history[-MAX_HISTORY_MESSAGES:]:
            messages.append(message)
        messages.append({'role': 'user', 'content': user_prompt})

        response = self._call_provider(messages)
        if not response or 'error' in response:
            return response or {'error': 'No response from provider'}

        reply = response.get('reply', response.get('content', ''))
        self.conversation_history.append({'role': 'user', 'content': user_prompt})
        self.conversation_history.append({'role': 'assistant', 'content': reply})
        self.last_used = datetime.now().isoformat()

        return {
            'reply': reply,
            'model': self.model,
            'provider': self.current_provider,
        }

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------

    def generate_report(self, scan_results, audience='technical'):
        """Produce a structured security report from the scan results."""
        context = self.build_context(scan_results)

        audience_guidance = {
            'executive': (
                "Write for a non-technical decision maker. Lead with business risk "
                "and impact in plain language, avoid jargon and raw payloads, and "
                "keep it short and prioritised."
            ),
            'technical': (
                "Write for engineers who will fix this. Include specific "
                "vulnerability classes, affected endpoints and parameters, and "
                "concrete remediation steps with code-level detail where useful."
            ),
            'full': (
                "Write a complete report. Cover the scope, the target's "
                "architecture, every finding grouped by severity with evidence, "
                "and detailed remediation. Be thorough."
            ),
        }.get(audience, 'Write a thorough technical report.')

        prompt = f"""Produce a security assessment report for this target.

{audience_guidance}

Use Markdown with these sections:

1. **Executive Summary** - what was found and why it matters
2. **Target Profile** - the stack, technologies, exposed ports, and any
   fingerprinting detail that shapes the risk
3. **Findings by Severity** - grouped Critical / High / Medium / Low, each
   finding with what it is, the evidence, impact, and the fix
4. **Remediation Plan** - ordered, concrete steps, highest risk first
5. **Conclusion** - residual risk and recommended next steps

Where a claim depends on something the scan did not confirm, say so explicitly.

SCAN DATA:
{self._context_prompt(context)}"""

        return self._run(prompt)

    def build_attack_plan(self, scan_results, scope_note=''):
        """Build a prioritised test plan for the findings.

        Scoped to authorised testing: this is a plan for a tester who already
        has permission to assess the target, not an autonomous exploit runner.
        """
        context = self.build_context(scan_results)
        note = scope_note.strip() or 'No additional scope notes supplied.'

        prompt = f"""Build an attack / test plan for this target, based on the scan findings.

AUTHORISATION: The tester states they have written permission to test this
target. Scope note: {note}

For each area of attack, provide:
- **Objective** - what the tester is trying to achieve
- **Why this target** - the specific finding, parameter or technology that
  makes this worth pursuing
- **Test steps** - concrete requests or checks to run, safe and non-destructive
- **Evidence that would confirm it** - how to know it worked
- **Expected impact if real**

Prioritise by likely impact and ease. Cover business logic and access control
where the findings point that way, not just injection. Note explicitly where a
test could be destructive and should be agreed in advance.

Keep every step to verification and proof-of-concept. Do not include
persistence, data exfiltration beyond proving access, or any step that would
damage data or take the service down.

SCAN DATA:
{self._context_prompt(context)}"""

        system_extra = (
            "You assist authorised security testing. You produce test plans and "
            "verification steps for professionals with written permission. You do "
            "not produce destructive payloads, persistence mechanisms, or guidance "
            "for attacking systems without authorisation. If asked for any of "
            "those, explain briefly why you cannot and offer the authorised "
            "alternative."
        )
        return self._run(prompt, system_extra=system_extra)

    def ask(self, question, scan_results=None):
        """Answer a question, using the scan results as context."""
        if not question or not question.strip():
            return {'error': 'A question is required'}

        context = self.build_context(scan_results) if scan_results else None

        if context:
            prompt = (
                f"SCAN DATA FOR CONTEXT:\n{self._context_prompt(context)}\n\n"
                f"QUESTION: {question.strip()}\n\n"
                "Answer using the scan data above. If the data does not answer "
                "the question, say so and explain what would need to be tested."
            )
        else:
            prompt = (
                f"QUESTION: {question.strip()}\n\n"
                "No scan results are loaded. Answer from general web security "
                "knowledge and say clearly when a target-specific answer would "
                "need scan data."
            )

        return self._run(prompt)

    def verify_credentials(self):
        """Check the configured credentials with a minimal request.

        Lets the UI confirm an API key works before the user relies on it.
        """
        if not self.client:
            return {'success': False, 'error': 'No provider configured'}

        result = self._call_provider([
            {'role': 'user', 'content': 'Reply with the single word: OK'}
        ])
        if result and 'error' in result:
            return {'success': False, 'error': result['error']}

        return {
            'success': True,
            'provider': self.current_provider,
            'model': self.model,
            'provider_name': self.providers.get(
                self.current_provider, {}).get('name', self.current_provider),
        }

    def describe(self):
        """Public description of this agent. Never includes the API key."""
        return {
            'session_id': self.session_id,
            'configured': bool(self.client),
            'provider': self.current_provider,
            'provider_name': self.providers.get(
                self.current_provider, {}).get('name'),
            'model': self.model,
            'messages': len(self.conversation_history),
            'created_at': self.created_at,
            'last_used': self.last_used,
        }

