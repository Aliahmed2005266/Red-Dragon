# 🐉 Red Dragon

**Red Dragon** - Professional Web Vulnerability Scanner by **aegis cyber works**

An advanced, fully automated web application security scanner with AI integration that performs comprehensive security testing against any web target. Features 19 specialized scanner modules covering OWASP Top 10 vulnerabilities, cloud security, AI/LLM security, API testing, fuzzing, subdomain enumeration, and more.

## ✨ Features

### 🔬 Vulnerability Scanning (19 Modules)
| Module | Detection Method | Severity Types |
|--------|-----------------|----------------|
| **SQL Injection** | Error-based, Boolean-based, Time-based, Union-based | High |
| **XSS** | Reflected, DOM-based, Event handlers, Encoded payloads | High |
| **IDOR** | Parameter ID manipulation, Sequential probing | High |
| **LFI/RFI** | Path traversal, PHP wrappers, File reads | Critical/High |
| **File Upload** | Malicious file types, RCE testing, Upload validation | Critical/High |
| **Command Injection** | Time-based, Output reflection, Blind injection | Critical |
| **GraphQL** | Introspection, Query batching, DoS via deep queries | Medium/High |
| **API Security** | Auth bypass, Rate limits, CORS, JWT validation | Medium/High |
| **Cloud Security** | AWS/GCP/Azure metadata, S3 exposure, Storage configs | Critical/High |
| **CVE Detection** | Version-based vulnerabilities, Known exploits | Varies |
| **WordPress** | Plugin/themes detection, Config leaks, User enumeration | Low->Critical |
| **Open Redirect** | Parameter injection, CRLF injection, JS redirects | High/Critical |
| **Port Scanner** | TCP connect scan, Service identification | Varies |
| **Firewall/WAF** | WAF fingerprinting, Bypass techniques | Info/High |
| **Rate Limiting** | General, Login, API endpoint testing | Medium/High |
| **General Security** | Headers, Cookies, Comments, JS analysis | Low->Medium |
| **AI/LLM Security** | OWASP Top 10 for LLM (Prompt Injection, DoS, etc.) | Critical/High |
| **Encoding Engine** | URL, Base64, Hex, Unicode, HTML entities | N/A (Helper) |

### 🎯 Specialized Reconnaissance
- **Fuzzer**: Wordlist-based directory and parameter fuzzing (40+ common paths)
- **Subdomain Enumeration**: DNS resolution, HTTP validation, Certificate Transparency logs
- **Site Mapper**: 2D interactive site mapping with relationship discovery
- **Web Proxy**: Request interception, modification, and replay capabilities

### 🧠 AI-Powered Security Analysis
- **OWASP Top 10 for LLM**: Tests prompt injection, sensitive disclosure, excessive agency, insecure output, model DoS, and more
- **AI Chat Interface**: Interactive security consultation with AI assistants
- **AI Analysis**: Automatic analysis of scan results with actionable remediation
- **Multiple AI Providers**: OpenAI, Anthropic Claude, Google Gemini, Mistral, Cohere support

### 🔐 Advanced Encoding & Decoding Support
- **11 Encoding Types**: URL, double URL, Base64, hex, Unicode, HTML entities, mixed case, null byte, tab whitespace, comment insertion, Unicode normalization
- **11 Decoding Types**: URL, double URL, Base64, hex, Unicode, HTML entities, mixed case, null byte, whitespace normalization, comment removal, Unicode normalization revert
- **Multi-layer Encoding**: Apply multiple encoding layers for deep WAF bypass
- **Automated Bypass Chains**: Generate complete bypass chains for each test
- **Auto-Detect Encoding**: Automatically detect encoding type and decode
- **Smart Decode**: Iteratively decode until no more changes detected
- **Brute Force Decode**: Try all decoding methods at once
- **Encoder/Decoder Tool**: Interactive CLI tool and web UI tab for encoding/decoding payloads

### 🧠 Smart Detection
- **Technology Fingerprinting**: Automatically detects 15+ web technologies (React, Angular, Vue, WordPress, Drupal, Joomla, Apache, Nginx, etc.)
- **Firewall/WAF Detection**: Identifies Cloudflare, AWS WAF, ModSecurity, Imperva, Akamai, F5 Big-IP, and more
- **Rate Limit Testing**: Tests general, login, and API rate limits
- **Automatic WordPress Detection**: Activates WordPress scanning when CMS is detected

### 📊 Professional Reports
- **Interactive Dashboard**: Real-time statistics, pie charts, severity distribution
- **Detailed Findings**: Expandable cards with payloads, evidence, and remediation
- **HTML Report Download**: Professional dark-themed PDF-ready reports
- **Severity Classification**: Critical/High/Medium/Low/Info with color coding
- **AI-Generated Analysis**: Optional AI-powered security recommendations

### 🎨 Modern Dark Theme UI
- Dark cyber-security themed interface with red/cyan color scheme
- Real-time scanning progress indicators
- Interactive severity charts (PieChart + BarChart)
- Expandable finding details with evidence and remediation steps
- Active scan management dashboard
- Module selection with 19+ scan categories
- Responsive design (mobile + desktop)

## 🖥️ Desktop Application

Red Dragon installs as a normal desktop application on **Windows** and **Linux**.
Every dependency, including the Python runtime and all scanner libraries, is
bundled into the installer, so the machine you install it on does not need
Python, Node.js or any system packages.

| Platform | Artefact | Notes |
| --- | --- | --- |
| Windows (x64) | `Red-Dragon-Setup-1.0.0.exe` | NSIS installer, per-user or per-machine, selectable install folder, Start menu and desktop shortcuts |
| Linux (x64) | `Red-Dragon-1.0.0.AppImage` | Single self-contained file, runs without installing |
| Linux (x64) | `red-dragon_1.0.0_amd64.deb` | For Debian, Ubuntu and derivatives |

### Installing

Download the installer and run it. On Linux, make the AppImage executable and
run it:

```bash
chmod +x Red-Dragon-1.0.0.AppImage
./Red-Dragon-1.0.0.AppImage
```

or install the package:

```bash
sudo dpkg -i red-dragon_1.0.0_amd64.deb
```

Nothing else to install. The app bundles Python, Flask, the AI provider SDKs and
the whole scanner engine. It also does not depend on `nmap`: port scanning uses
raw sockets, so there is no system package to chase down.

### Building the installers

Requires Node.js 16+, npm 8+, and Python 3.8+ **on the build machine only**.

```bash
npm install                     # desktop shell + build tooling
cd frontend && npm install --legacy-peer-deps && cd ..

npm run dist:win                # Windows installer  -> release/
npm run dist:linux              # Linux AppImage + deb -> release/
npm run dist                    # whatever the host OS can build
```

`npm run dist` performs three steps in order:

1. `build:ui` compiles the React interface with a production build
2. `build:backend` freezes the Python engine into a self-contained bundle with
   PyInstaller, including the interface
3. `electron-builder` wraps the shell and the engine into the installer

The build stops with a clear message if the interface has not been built, if
PyInstaller is missing, or if the engine is produced without its interface, so a
half-built installer never reaches the release folder.

### How the desktop app is put together

```
+---------------------------------------------+
|  Electron shell  (desktop/main.js)          |
|   window, sandbox, no remote content        |
+---------------------------------------------+
|  Python engine  (packaged by PyInstaller)   |
|   127.0.0.1 only, free port, launch token   |
|   serves the built React interface          |
+---------------------------------------------+
```

The shell starts the engine, waits for it to report which port and token it
chose, then points the window at it. The engine serves both the API and the
interface, so the app is same-origin and needs no CORS permission at all. The
engine is a windowed binary, so on Windows it has no console; the start-up
handshake is written to a file the shell names, and the shell also reads stdout
as a fallback for development.

Only one copy of the app runs at a time, and the engine is always shut down with
the window so no server is left listening.

### Security posture of the installed app

Because a vulnerability scanner can be aimed at any host, the packaged app is
locked down more tightly than the development server:

- **Loopback only.** The engine binds `127.0.0.1` on a free port, never
  `0.0.0.0`, so it is unreachable from the local network. The Flask debugger is
  never enabled.
- **A launch token on every API call.** A local HTTP service with no
  authentication can be driven by any web page the user visits, which would turn
  a routine page load into an attack. The engine issues a random per-launch
  token, injects it into the page it serves, and rejects any `/api` call without
  it. The comparison is constant time.
- **A sandboxed renderer.** Context isolation on, Node integration off, and the
  Chromium sandbox on, so page script has no filesystem or process access.
- **Navigation and popups blocked.** The window cannot be navigated off the
  loopback origin; external links open in the system browser instead.
- **Device permissions denied.** No camera, microphone or notifications.
- **API keys are never written to disk.** They live in memory for the lifetime
  of an AI session. The settings file has no key field, and any key submitted
  to the settings endpoint is dropped.
- **Reports escape attacker-controlled data**, so a reflected payload cannot
  become stored XSS in an exported report.

### Settings storage

Preferences live in the per-user application data directory, not next to the
executable, so they survive a reinstall and work when the app is installed in a
protected location:

| Platform | Location |
| --- | --- |
| Windows | `%APPDATA%\RedDragon\settings.json` |
| macOS | `~/Library/Application Support/RedDragon/settings.json` |
| Linux | `~/.config/red-dragon/settings.json` |

The file is written atomically and created with user-only permissions, because
it records which hosts have been scanned.

### Running from source

```bash
npm run dev            # backend + React dev server together
npm start              # the desktop shell, using the source tree
npm run backend:debug  # just the engine, with the token guard enabled
```

`npm start` looks for a Python that can import Flask, so activate a virtualenv
first if that is where the dependencies are installed.

### Tests

```bash
npm run test:backend     # all Python test suites
npm run test:desktop     # the Electron shell and engine lifecycle
npm run test:packaging   # installer configuration, offline
```
## 📚 API Endpoints

### Core Scan Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Start a new scan |
| `GET` | `/api/scan/<id>/status` | Get scan status |
| `GET` | `/api/scan/<id>/results` | Get scan results |
| `GET` | `/api/scan/<id>/report` | Download HTML report |
| `POST` | `/api/scan/deep` | Deep scan (fuzzing + subdomains + mapping) |
| `GET` | `/api/health` | Server health check |

### Extended Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/fuzz` | Fuzz target with wordlist |
| `GET` | `/api/fuzz/wordlist/builtin` | Get built-in wordlist |
| `POST` | `/api/subdomains` | Enumerate subdomains |
| `GET` | `/api/subdomains/wordlist` | Get subdomain wordlist |
| `POST` | `/api/map` | Generate 2D site map |
| `POST` | `/api/proxy/history` | Get intercepted requests |
| `POST` | `/api/proxy/replay` | Replay modified request |
| `POST` | `/api/network/start` | Start network capture |
| `GET` | `/api/network/packets` | Get captured packets |

### AI Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/ai/providers` | List available AI providers |
| `POST` | `/api/ai/configure` | Configure AI provider |
| `POST` | `/api/ai/chat` | Chat with AI |
| `POST` | `/api/ai/analyze` | Analyze scan results with AI |
| `POST` | `/api/ai/clear` | Clear conversation history |
| `POST` | `/api/ai/remediation` | Generate remediation summary |

### AI Security Agent Endpoints
Session-scoped agent. Each session holds its own API key in memory; the key is
never written to disk and never returned by any endpoint.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/ai/session` | Create a session with a user-supplied API key (verified before use) |
| `GET` | `/api/ai/session/<id>` | Describe a session (never includes the key) |
| `DELETE` | `/api/ai/session/<id>` | End the session and discard the key |
| `POST` | `/api/ai/agent/ask` | Ask a question, answered using the scan results as context |
| `POST` | `/api/ai/agent/report` | Generate a report (`audience`: executive / technical / full) |
| `POST` | `/api/ai/agent/attack-plan` | Build a test plan (requires `authorised: true`) |

Both the agent and the reporting endpoints accept either `scan_id` (resolved
server-side) or `scan_results` to attach scan context.

### Encoder/Decoder Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/encode` | Encode a payload with specified encoding type |
| `POST` | `/api/decode` | Decode a payload with specified decoding type |
| `GET` | `/api/encodings` | List all available encoding/decoding types |
| `POST` | `/api/decode/smart` | Iteratively decode until no more changes detected |
| `POST` | `/api/decode/brute` | Try all decoding methods and return all results |
| `POST` | `/api/detect` | Auto-detect encoding type and decode |
| `POST` | `/api/decode/all` | Apply all decodings to a payload |

## 🖥️ CLI Usage

The scanner includes a full-featured command-line interface (`cli_scanner.py`) with an interactive menu system.

### Run CLI Mode
```bash
python cli_scanner.py
```

### CLI Menu Options
```
1.  Full Scan (all modules)
2.  SQL Injection only
3.  XSS only
4.  LFI/RFI only
5.  Command Injection only
6.  File Upload only
7.  API Security only
8.  Cloud Security only
9.  AI/LLM Security only
10. WordPress vulnerabilities only
11. Open Redirect only
12. Port Scanner only
13. Firewall & Rate Limit detection only
14. Encoder/Decoder Tool  <- NEW
```

### Encoder/Decoder Tool (Option 14)
```
1. URL Encode
2. Base64 Encode
3. Hex Encode
4. Unicode Encode
5. HTML Entity Encode
6. URL Decode
7. Base64 Decode
8. Hex Decode
9. Unicode Decode
10. HTML Entity Decode
11. Auto-Detect & Decode
12. Smart Decode (Iterative)
13. Brute Force (Try All)
0. Back to Main Menu
```

### Example: Start a Scan
### Example: Start a Scan
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com", "modules": ["all"]}'
```

## 🏗️ Architecture

```
red-dragon/
+-- package.json                  # Desktop app + installer configuration
+-- desktop/                      # Electron shell
|   +-- main.js                   # Window, sandbox, engine lifecycle
|   +-- preload.js                # Minimal contextBridge surface
|   +-- backend.js                # Starts and supervises the Python engine
+-- scripts/
|   +-- build-backend.js          # Bundles the engine with PyInstaller
|   +-- make_icon.py              # Generates the app icons
|   +-- test-desktop.js           # Shell and engine lifecycle tests
|   +-- test-packaging.js         # Installer configuration tests
+-- packaging/
|   +-- red-dragon-backend.spec   # PyInstaller specification
+-- backend/
|   +-- server.py                 # Flask API server
|   +-- desktop.py                # Hardened entry point used by the app
|   +-- config_store.py           # Per-user settings (never API keys)
|   +-- server_extensions.py      # Extended API endpoints
|   +-- requirements.txt          # Python dependencies
|   +-- reports/                  # Generated HTML reports
|   +-- scanner_modules/
|   |   +-- sql_injection.py         # SQLi detection
|   |   +-- xss_scanner.py           # XSS detection
|   |   +-- idor_scanner.py          # IDOR detection
|   |   +-- lfi_scanner.py           # LFI detection
|   |   +-- file_upload_scanner.py   # File upload testing
|   |   +-- command_injection.py     # Command injection
|   |   +-- graphql_scanner.py       # GraphQL testing
|   |   +-- api_scanner.py           # API security
|   |   +-- cloud_scanner.py         # Cloud vulns (AWS/GCP/Azure)
|   |   +-- cve_scanner.py           # CVE matching
|   |   +-- wordpress_scanner.py     # WordPress testing
|   |   +-- ai_scanner.py            # AI/LLM security (OWASP Top 10)
|   |   +-- general_scanner.py       # General security audit
|   |   +-- port_scanner.py          # Port scanning (raw sockets)
|   |   +-- firewall_detector.py     # WAF fingerprinting
|   |   +-- rate_limit_tester.py     # Rate limit testing
|   |   +-- open_redirect_scanner.py # Open redirect testing
|   |   +-- encoding_handler.py      # Encoded payload engine
|   |   +-- fuzzer.py                # Wordlist-based fuzzing
|   |   +-- subdomain_enum.py        # Subdomain enumeration
|   |   +-- site_mapper.py           # 2D site mapping
|   |   +-- finding_dedupe.py        # Duplicate finding collapse
|   |   +-- poc_evidence.py          # Request/response evidence capture
|   |   +-- param_discovery.py       # Parameter discovery + probing
|   |   +-- tech_fingerprint.py      # Architecture fingerprinting
|   |   +-- web_proxy.py             # Request interception
|   +-- ai_agent.py                  # AI assistant integration
+-- frontend/                     # React interface (served by the engine)
|   +-- package.json
|   +-- public/
|   |   +-- index.html
|   +-- src/
|       +-- App.js                    # React main component (full UI)
|       +-- App.css                   # Dark theme styling
|       +-- index.js                  # React entry point
+-- cli_scanner.py                    # Command-line interface
+-- README.md                         # This file
```

## 🔍 Scanner Module Details

### SQL Injection Scanner
- Tests 25+ SQL injection payloads
- Supports MySQL, PostgreSQL, MSSQL, Oracle, SQLite
- Error-based, boolean-based, and time-based detection
- Form parameter and URL parameter analysis

### XSS Scanner
- Tests 32+ XSS payloads
- Context-aware payload generation
- Script, img, svg, body, input, select, textarea, marquee, audio, video vectors
- Encoding bypass variants
- Pattern-based detection

### AI/LLM Security Scanner (OWASP Top 10 for LLM)
- **LLM01**: Prompt Injection (direct and indirect)
- **LLM02**: Sensitive Information Disclosure
- **LLM03**: Supply Chain Vulnerabilities
- **LLM04**: Insecure Plugin/Extension Design
- **LLM05**: Excessive Agency
- **LLM06**: Overreliance on LLM Output
- **LLM07**: Insecure Output Handling (XSS)
- **LLM08**: Training Data Poisoning
- **LLM09**: Model Denial of Service
- **LLM10**: Model Theft/Extraction

### Fuzzer Module
- Built-in wordlist with 40+ common directories and files
- Custom wordlist support
- Parallel scanning with configurable threads
- Smart classification (admin, API, config, backup)
- Status code and response size analysis

### Subdomain Enumeration
- DNS resolution (A and CNAME records)
- HTTP/HTTPS validation
- Certificate Transparency log search (crt.sh)
- 100+ common subdomain wordlist
- Interesting subdomain detection (admin, dev, staging, etc.)

### Site Mapper
- Recursive web crawling (up to configurable depth)
- 2D graph visualization data (vis.js format)
- Relationship discovery (API clusters, admin panels)
- Page type classification
- Form and resource extraction

### Open Redirect Scanner
- Tests 23+ redirect bypass payloads
- Protocol-based, path-based, encoding-based attacks
- CRLF injection for header-based redirects
- JavaScript redirect detection
- Meta-refresh detection
- 45+ redirect parameter detection

### Encoding Engine
- **URL Encoding**: Standard and double URL encoding
- **Base64**: Standard Base64 with padding
- **Hex Encoding**: Full hex string conversion
- **Unicode Encoding**: Full Unicode escape sequences
- **HTML Entity**: Full HTML entity encoding
- **Mixed Case**: Case alternation for signature bypass
- **Null Byte**: Null byte injection (%00)
- **Tab Whitespace**: Whitespace replacement for SQLi bypass
- **Comment Insertion**: Inline comment insertion
- **Multi-layer**: Combined encoding chains
- **Bypass Chain**: Full bypass chain generation

### Finding Deduplication

A single scan routinely reports the same issue many times: the dedicated
module and the "web" group both cover WordPress, XXE and SSTI; a scanner that
tries a list of payloads reports every variant; and some scanners report a
finding against both the bare endpoint and the URL carrying the target's
original query string.

`scanner_modules/finding_dedupe.py` collapses these by giving every finding a
stable identity:

- **Vulnerability class** - scanner type strings are canonicalised, so `SQLi`,
  `SQL Injection` and `SQL Injection (SQLi)` are one class.
- **Normalised location** - default ports, trailing slashes, host case and
  fragment are ignored, and parameter *values* are replaced with `*` so the
  same endpoint always produces the same string. When the parameter is known it
  is compared separately and the query is dropped, otherwise a finding recorded
  against `/search` and one recorded against `/search?q=x` would never match.
- **Parameter name** - so `/a?id=` and `/a?page=` stay distinct.

Duplicates are **merged, not discarded**: the highest severity wins, the longer
description wins, every payload is collected in `payloads`, evidence strings in
`evidence_list`, the reporting modules in `modules`, and alternative titles in
`variants`. The most convincing proof of concept is kept (a reflected-payload
marker with a response excerpt outranks a bare pattern match). Findings are then
sorted so Critical and High surface first.

The results payload reports what happened under `dedupe_stats`
(`original`, `unique`, `merged`), the UI shows a "N merged" chip and a
"Corroborating detail" block, and the HTML report includes the same block.
Everything merged in comes from the target, so it is HTML-escaped on export.

## 🤖 AI Integration

### Supported AI Providers
- **OpenAI**: GPT-4, GPT-3.5, and other models
- **Anthropic**: Claude 3 (Opus, Sonnet, Haiku)
- **Google**: Gemini Pro, Gemini Ultra
- **Mistral**: Mistral models via Mistral API
- **Cohere**: Command models

The model dropdown lists a few well-known models per provider, plus a
**Custom model...** option: type any model name your provider accepts
(newer releases, aliases, or your own fine-tuned models) and the agent will
use exactly that name. The preset list is a convenience, not an allow-list.

### AI Features
1. **AI Chat**: Ask questions about security, vulnerabilities, and remediation
2. **AI Analysis**: Get comprehensive security analysis of scan results
3. **AI Remediation**: Generate detailed remediation plans
4. **Scan Context**: AI understands your scan results and provides tailored advice
5. **Custom Models**: Choose "Custom model..." and type any model name your provider offers

### Example: AI Configuration
```bash
curl -X POST http://localhost:5000/api/ai/configure \
  -H "Content-Type: application/json" \
  -d '{"provider": "openai", "api_key": "your-key", "model": "gpt-4"}'
```

## ⚙️ Configuration

### Scan Configuration (in server.py)
```python
self.scan_config = {
    'deep_scan': True,        # Enable deep scanning
    'aggressive_mode': False, # Enable aggressive (noisier) scanning
    'test_wordpress': False,  # Force WordPress scanning
    'stealth_mode': False     # Enable stealth (slower) scanning
}
```

## 🛡️ Security Headers Checked
| Header | Purpose |
|--------|---------|
| `X-Frame-Options` | Clickjacking protection |
| `X-Content-Type-Options` | MIME sniffing protection |
| `X-XSS-Protection` | XSS filter |
| `Strict-Transport-Security` | HTTPS enforcement |
| `Content-Security-Policy` | Content Security Policy |
| `Referrer-Policy` | Referrer policy |
| `Permissions-Policy` | Feature permissions |

## 🎯 Supported Technologies Detected
- **CMS**: WordPress, Drupal, Joomla
- **Frontend**: React, Angular, Vue.js, jQuery, Bootstrap
- **Backend**: PHP, ASP.NET, Node.js, Python (Django/Flask)
- **Servers**: Apache, Nginx
- **AI/LLM**: OpenAI, Anthropic, Google, Mistral, Cohere, HuggingFace, Azure OpenAI, AWS Bedrock

## 📝 Use Cases
- **Security Audits**: Comprehensive web application security testing
- **Penetration Testing**: Automated vulnerability discovery
- **Compliance**: Check for OWASP Top 10 compliance
- **AI Security Testing**: Test LLM-powered applications
- **Bug Bounty**: Accelerate vulnerability discovery
- **DevSecOps**: Integrate into CI/CD pipelines
- **Red Teaming**: Advanced reconnaissance and exploitation testing

## 📝 License
MIT License - Free for personal and commercial use.

## ⚠️ Disclaimer
This tool is for authorized security testing only. Always ensure you have explicit permission before scanning any target. Unauthorized scanning may be illegal in your jurisdiction. The authors are not responsible for misuse of this tool.

## 🤝 Contributing
Contributions welcome! Please submit pull requests for:
- New vulnerability detection modules
- Additional encoding/obfuscation techniques
- Improved detection patterns
- UI/UX enhancements
- Bug fixes
- Documentation improvements
- AI integration enhancements

## 🌟 Star History
If you find this tool useful, please star the repository to show support!

---

**Made with ❤️ by aegis cyber works for the security community**

**Red Dragon** - Your comprehensive web application security companion.