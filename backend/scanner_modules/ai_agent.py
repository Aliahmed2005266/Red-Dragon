"""
AI Agent Module - Multi-provider AI support (OpenAI, Claude, Gemini, etc.)
"""

import json
import time

# Longest model name accepted from a client. Real provider model ids are far
# shorter; the cap keeps an oversized user-typed string out of provider
# requests.
MAX_MODEL_NAME_LENGTH = 200


def normalize_model_name(model):
    """Validate and clean a user-supplied model name.

    Any name the provider accepts is allowed - not only the presets listed in
    ``MultiProviderAIAgent.providers`` - because providers ship new models
    faster than those lists are updated, so the user can name any model
    directly (including fine-tuned or newer ones).

    Returns the trimmed name, or None when nothing usable was given, which
    tells the caller to fall back to the provider's default model.

    Raises ValueError with a message safe to show the user when the value
    cannot be used.
    """
    if model is None:
        return None
    if not isinstance(model, str):
        raise ValueError('Model name must be a string')
    model = model.strip()
    if len(model) > MAX_MODEL_NAME_LENGTH:
        raise ValueError(
            f'Model name is too long (max {MAX_MODEL_NAME_LENGTH} characters)')
    return model or None


class MultiProviderAIAgent:
    def __init__(self):
        self.providers = {
            'openai': {
                'name': 'OpenAI',
                'models': ['gpt-4', 'gpt-4-turbo', 'gpt-3.5-turbo'],
                'default_model': 'gpt-4'
            },
            'anthropic': {
                'name': 'Anthropic (Claude)',
                'models': ['claude-3-5-sonnet-20241022', 'claude-3-opus-20240229', 'claude-3-haiku-20240307'],
                'default_model': 'claude-3-5-sonnet-20241022'
            },
            'google': {
                'name': 'Google (Gemini)',
                'models': ['gemini-1.5-pro', 'gemini-1.0-pro', 'gemini-1.5-flash'],
                'default_model': 'gemini-1.5-pro'
            },
            'mistral': {
                'name': 'Mistral AI',
                'models': ['mistral-large-latest', 'mistral-medium-latest', 'open-mistral-7b'],
                'default_model': 'mistral-large-latest'
            },
            'cohere': {
                'name': 'Cohere',
                'models': ['command', 'command-light', 'command-nightly'],
                'default_model': 'command'
            }
        }
        
        self.current_provider = None
        self.api_key = None
        self.model = None
        self.client = None
        self.conversation_history = []
        # Response size caps, overridable by subclasses (reports need more room)
        self.max_tokens = 1500
        self.temperature = 0.5
    
    def get_available_providers(self):
        """Get list of available AI providers"""
        return self.providers
    
    def set_provider(self, provider_name, api_key, model=None):
        """Configure AI provider.

        ``model`` may be any model name the provider accepts, not only the
        presets in ``self.providers`` - the preset list is a convenience for
        the UI, not an allow-list. Invalid values are rejected rather than
        silently falling back so the user notices the typo.
        """
        if provider_name not in self.providers:
            return {'success': False, 'error': f'Unknown provider: {provider_name}'}

        try:
            model = normalize_model_name(model)
        except ValueError as exc:
            return {'success': False, 'error': str(exc)}

        self.current_provider = provider_name
        self.api_key = api_key
        self.model = model or self.providers[provider_name]['default_model']
        self.client = self._create_client(provider_name, api_key)
        
        if self.client:
            return {
                'success': True,
                'provider': provider_name,
                'model': self.model,
                'name': self.providers[provider_name]['name']
            }
        else:
            return {'success': False, 'error': 'Failed to initialize client'}
    
    def _create_client(self, provider_name, api_key):
        """Create AI client based on provider"""
        try:
            if provider_name == 'openai':
                import openai
                return openai.OpenAI(api_key=api_key)
            
            elif provider_name == 'anthropic':
                import anthropic
                return anthropic.Anthropic(api_key=api_key)
            
            elif provider_name == 'google':
                import google.generativeai as genai
                genai.configure(api_key=api_key)
                return genai
            
            elif provider_name == 'mistral':
                from mistralai import Mistral
                return Mistral(api_key=api_key)
            
            elif provider_name == 'cohere':
                import cohere
                return cohere.Client(api_key=api_key)
            
            else:
                return None
        except ImportError as e:
            print(f"Missing library for {provider_name}: {e}")
            return None
        except Exception as e:
            print(f"Error creating {provider_name} client: {e}")
            return None
    
    def chat(self, message, scan_context=None):
        """Chat with AI using configured provider"""
        if not self.client:
            return {"error": "No AI provider configured. Please select a provider and enter your API key."}
        
        try:
            system_prompt = "You are a cybersecurity AI assistant integrated into Red Dragon vulnerability scanner."
            
            if scan_context:
                findings = scan_context.get('findings', [])
                stats = scan_context.get('statistics', {})
                
                finding_types = {}
                for f in findings:
                    ftype = f.get('type', 'Unknown')
                    if ftype not in finding_types:
                        finding_types[ftype] = {'count': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Critical': 0, 'examples': []}
                    finding_types[ftype]['count'] += 1
                    sev = f.get('severity', 'Info')
                    if sev in finding_types[ftype]:
                        finding_types[ftype][sev] += 1
                    if len(finding_types[ftype]['examples']) < 2:
                        finding_types[ftype]['examples'].append(f.get('title', ''))
                
                system_prompt += f"""
                
Current Scan Context:
- Target: {scan_context.get('target', 'N/A')}
- Total Findings: {stats.get('total_findings', 0)} (C:{stats.get('critical', 0)} H:{stats.get('high', 0)} M:{stats.get('medium', 0)} L:{stats.get('low', 0)} I:{stats.get('info', 0)})
- Technologies: {', '.join(scan_context.get('technologies', ['N/A']))}
- Firewall: {scan_context.get('firewall', 'None')}

Finding Breakdown:
{json.dumps(finding_types, indent=2)}

You can help the user understand these findings, suggest remediation steps, explain vulnerabilities, or provide security recommendations.
Keep responses focused on web security and the scan results.
"""
            
            messages = [
                {"role": "system", "content": system_prompt}
            ]
            
            for msg in self.conversation_history[-10:]:
                messages.append(msg)
            
            messages.append({"role": "user", "content": message})
            
            response = self._call_provider(messages)
            
            if response and 'error' not in response:
                reply = response.get('reply', response.get('content', ''))
                self.conversation_history.append({"role": "user", "content": message})
                self.conversation_history.append({"role": "assistant", "content": reply})
                
                return {
                    'reply': reply,
                    'model': self.model,
                    'provider': self.current_provider
                }
            else:
                return response
            
        except Exception as e:
            return {"error": f"Chat error: {str(e)}"}
    
    def _call_provider(self, messages):
        """Call the configured AI provider"""
        try:
            if self.current_provider == 'openai':
                return self._call_openai(messages)
            elif self.current_provider == 'anthropic':
                return self._call_anthropic(messages)
            elif self.current_provider == 'google':
                return self._call_google(messages)
            elif self.current_provider == 'mistral':
                return self._call_mistral(messages)
            elif self.current_provider == 'cohere':
                return self._call_cohere(messages)
            else:
                return {"error": "Unsupported provider"}
        except Exception as e:
            return {"error": str(e)}
    
    def _call_openai(self, messages):
        """Call OpenAI API"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.5,
                max_tokens=self.max_tokens
            )
            return {'reply': response.choices[0].message.content}
        except Exception as e:
            return {"error": f"OpenAI error: {str(e)}"}
    
    def _call_anthropic(self, messages):
        """Call Anthropic Claude API"""
        try:
            system_msg = None
            user_messages = []
            
            for msg in messages:
                if msg['role'] == 'system':
                    system_msg = msg['content']
                else:
                    user_messages.append(msg)
            
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system_msg,
                messages=user_messages
            )
            return {'reply': response.content[0].text}
        except Exception as e:
            return {"error": f"Anthropic error: {str(e)}"}
    
    def _call_google(self, messages):
        """Call Google Gemini API"""
        try:
            model = self.client.GenerativeModel(self.model)
            
            # Convert messages to Gemini format
            system_prompt = ""
            chat_history = []
            
            for msg in messages:
                if msg['role'] == 'system':
                    system_prompt = msg['content']
                elif msg['role'] == 'user':
                    chat_history.append({'role': 'user', 'parts': [msg['content']]})
                elif msg['role'] == 'assistant':
                    chat_history.append({'role': 'model', 'parts': [msg['content']]})
            
            if system_prompt:
                chat_history.insert(0, {'role': 'user', 'parts': [system_prompt]})
            
            chat = model.start_chat(history=chat_history[:-1] if len(chat_history) > 1 else [])
            response = chat.send_message(chat_history[-1]['parts'][0] if chat_history else "")
            
            return {'reply': response.text}
        except Exception as e:
            return {"error": f"Google Gemini error: {str(e)}"}
    
    def _call_mistral(self, messages):
        """Call Mistral AI API"""
        try:
            response = self.client.chat.complete(
                model=self.model,
                messages=messages,
                temperature=0.5,
                max_tokens=self.max_tokens
            )
            return {'reply': response.choices[0].message.content}
        except Exception as e:
            return {"error": f"Mistral error: {str(e)}"}
    
    def _call_cohere(self, messages):
        """Call Cohere API"""
        try:
            # Convert messages to Cohere format
            system_prompt = ""
            user_message = ""
            
            for msg in messages:
                if msg['role'] == 'system':
                    system_prompt = msg['content']
                elif msg['role'] == 'user':
                    user_message = msg['content']
            
            response = self.client.chat(
                message=user_message,
                model=self.model,
                preamble=system_prompt if system_prompt else None,
                temperature=0.5,
                max_tokens=self.max_tokens
            )
            return {'reply': response.text}
        except Exception as e:
            return {"error": f"Cohere error: {str(e)}"}
    
    def analyze_findings(self, scan_results):
        """Use AI to analyze and organize scan findings"""
        if not self.client:
            return {"error": "No AI provider configured. Please select a provider and enter your API key."}
        
        try:
            findings_summary = []
            for finding in scan_results.get('findings', []):
                findings_summary.append({
                    'type': finding.get('type', 'Unknown'),
                    'severity': finding.get('severity', 'Info'),
                    'title': finding.get('title', ''),
                    'description': finding.get('description', ''),
                    'url': finding.get('url', ''),
                    'remediation': finding.get('remediation', ''),
                })
            
            stats = scan_results.get('statistics', {})
            
            prompt = f"""You are a cybersecurity AI assistant. Analyze the following vulnerability scan results and provide:
1. EXECUTIVE SUMMARY - A brief summary for management
2. CRITICAL FINDINGS - List all critical/high severity findings that need immediate attention
3. PRIORITIZED REMEDIATION - Step-by-step remediation plan ordered by severity
4. TECHNICAL NOTES - Additional technical insights about the vulnerabilities
5. RISK ASSESSMENT - Overall risk score (0-100) and assessment

Target URL: {scan_results.get('target', 'N/A')}
Domain: {scan_results.get('domain', 'N/A')}
Firewall Detected: {scan_results.get('firewall', 'None')}
Technologies: {', '.join(scan_results.get('technologies', ['None detected']))}

Statistics:
- Total Findings: {stats.get('total_findings', 0)}
- Critical: {stats.get('critical', 0)}
- High: {stats.get('high', 0)}
- Medium: {stats.get('medium', 0)}
- Low: {stats.get('low', 0)}
- Info: {stats.get('info', 0)}

Findings ({len(findings_summary)} total):
{json.dumps(findings_summary[:50], indent=2)}

Please provide a comprehensive, professional security analysis."""
            
            messages = [
                {"role": "system", "content": "You are an expert cybersecurity analyst. Provide detailed, professional vulnerability analysis."},
                {"role": "user", "content": prompt}
            ]
            
            response = self._call_provider(messages)
            
            if response and 'error' not in response:
                analysis = response.get('reply', response.get('content', ''))
                return {
                    'analysis': analysis,
                    'model': self.model,
                    'provider': self.current_provider,
                    'tokens_used': 'N/A'
                }
            else:
                return response
            
        except Exception as e:
            return {"error": f"AI analysis error: {str(e)}"}
    
    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history = []
        return True


# Global AI agent instance
ai_agent = MultiProviderAIAgent()