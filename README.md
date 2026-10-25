# BaitZero

> Intelligent, privacy-preserving desktop link protection and deep URL investigation to help users make safer browsing decisions.

BaitZero is a lightweight Windows desktop security utility designed to inspect suspicious links before they can lead to credential theft, malware delivery, or phishing compromises. Combining instant offline heuristic inspection with on-demand deep network investigation, BaitZero analyzes incoming URLs from manual entry, clipboard activity, system notifications, and web browser navigation.

---

## 📋 Overview

Modern social engineering attacks increasingly rely on lookalike domains, obfuscated URLs, deceptive subdomains, and multi-hop redirects. Many users click links without knowing where they truly lead or what infrastructure hosts them.

BaitZero addresses this challenge by providing an intuitive, multi-layered analysis pipeline:
1. **Instant Offline Heuristic Analysis**: Evaluates URL syntax, brand lookalikes, userinfo `@` obfuscation, multi-part ccTLDs, and suspicious path tokens immediately on-device without sending data across the network.
2. **On-Demand Deep Research**: When deeper inspection is requested, BaitZero runs targeted network probes covering domain registration (RDAP), DNS records (via DNS-over-HTTPS), direct TLS certificate verification, threat reputation feeds, and redirect chains.

> **Important Security Distinction**: Automated risk scores and detection flags are decision-support signals designed to highlight known threats and structural anomalies. They do not constitute an absolute guarantee that an unflagged link is safe or that all zero-day threats will be caught.

---

## ✨ Key Features

### 🔍 Instant Scan & Heuristic Engine
- **URL Structure Breakdown**: Parses protocol, host, port, path, query parameters, and fragments.
- **Authority & Obfuscation Detection**: Detects userinfo `@` symbols designed to deceive readers about the destination host (distinguishing authority tokens from harmless query parameters).
- **Brand Boundary Matching**: Flags targeted brand impersonation in subdomains or anomalous domain names while avoiding naive substring false positives (e.g., distinguishing legitimate domain boundaries from lookalikes).
- **Multi-Part ccTLD Resolution**: Correctly resolves second-level country domains (such as `.co.uk`, `.com.au`, and `.co.jp`) to prevent deceptive parent domain misclassification.
- **IP Literal Detection**: Detects raw IPv4 and IPv6 literal hosts used in place of standard domain names.
- **Plain-Language Explanations**: Generates concise, understandable summaries explaining why a link received a particular risk level (Low, Medium, or High).

### 🔬 Deep Research & Expandable Evidence Cards
When deeper investigation is triggered, BaitZero launches on-demand asynchronous probes and renders interactive, expandable finding cards equipped with full keyboard accessibility (`Enter`/`Space`), ARIA control states, and smooth animated expansion drawers:

| Investigation Module | Upstream Source / Protocol | What It Examines |
| :--- | :--- | :--- |
| **Domain Registration** | RDAP (`rdap.org` bootstrap) | Registrable domain, registrar identity, creation date, expiration date, and EPP status codes. |
| **DNS Records** | DNS-over-HTTPS (Cloudflare DoH) | Resolved A (IPv4) and AAAA (IPv6) records, resolution protocol, and SSRF perimeter safety. |
| **TLS Certificate** | Direct In-Band TLS Handshake | Subject DN, issuer DN, root trust store verification, validity dates, and Subject Alternative Names (SANs). |
| **Threat Reputation** | abuse.ch URLhaus API | Active threat feed matches, malware distribution categories, and threat record counts. |
| **Redirect Chain** | Hop-by-Hop SSRF-Safe HTTP Tracer | Sequence of hops, HTTP status codes, intermediate IP addresses, next location headers, and final destination URL. |

- **Unavailable Service Protection**: If a reputation service is unreachable or responds with an HTTP 401/timeout, BaitZero explicitly marks the check as `Unavailable` and displays a security advisory. An unavailable check is **never** interpreted as a clean or safe reputation result.
- **Auto-Expansion of Anomalies**: Any probe returning a suspicious finding automatically expands its review drawer upon completion so risks are immediately prominent.

### 📋 Clipboard & System Notification Monitoring
- **Intelligent Clipboard Detection**: Monitors newly copied text for valid URLs. Sequences are tracked and deduplicated so repeated polling of an unchanged clipboard never produces redundant alerts or duplicate history entries.
- **Windows Notification Extraction**: Captures URLs originating from incoming Windows notifications (such as chat applications like WhatsApp or Discord), displaying the source application badge alongside the link.
- **Context-Aware Floating Alerts**: Renders a compact, translucent floating alert pill with distinct layout modes:
  - **Mode A (Security Notifications)**: Anchored to standard notification toast positioning.
  - **Mode B (Clipboard Detections)**: Positioned near active workflow areas.

### 🛡️ Scan History & Privacy Safeguards
- **Local History Ring Buffer**: Automatically maintains up to 100 recent scan records in local storage using a strict FIFO cap.
- **Data Minimization & Sanitization**:
  - URL query strings, sensitive tokens, passwords, and fragments are stripped prior to storage.
  - Notification message bodies, sender identities, and non-URL text are discarded immediately after URL extraction.
  - Raw clipboard content (such as copied passwords) is never stored in memory or persisted to disk.

### 🌐 Browser Extension Integration
- **Manifest V3 Extension**: Companion browser extension (`browser-extension/`) that intercepts navigation requests and verifies URLs against BaitZero's local engine.
- **Loopback IPC Endpoint**: Integrates via a local loopback HTTP service (`127.0.0.1:27432`) secured by token-based authentication (`X-Extension-Token`) stored locally in `%APPDATA%\LinkProtection\`.

---

## 🛠️ Technology Stack

- **Frontend Application**:
  - Vanilla JavaScript (ES Modules)
  - HTML5 & Responsive Semantic Markup
  - Vanilla CSS (Dark mode, glassmorphism design tokens, micro-animations)
  - [Vite](https://vitejs.dev/) (Frontend bundling & local development server)
- **Desktop Runtime & Native Backend**:
  - [Rust](https://www.rust-lang.org/) (2021 Edition)
  - [Tauri v2](https://v2.tauri.app/) (`@tauri-apps/api`, custom protocol handling, native system tray, multi-window support)
- **Core Rust Dependencies**:
  - `windows` (Win32 API bindings for notifications, window management, and COM)
  - `tokio` (Asynchronous runtime for deep probes and socket operations)
  - `reqwest` & `native-tls` (TLS connection handling and HTTP probe transport)
  - `x509-parser` (X.509 leaf certificate validation and attribute extraction)
  - `url` (Strict RFC URL parsing and normalization)
  - `serde` & `serde_json` (Type serialization and structured IPC schema)
  - `subtle` (Constant-time token comparisons)
- **Browser Extension**:
  - Chrome / Chromium Manifest V3 (`webNavigation`, `storage`, `tabs` permissions)
- **Build & Test Automation**:
  - Node.js & npm
  - Cargo & rustc
  - PowerShell scripting suite (`scripts/`)

---

## 🔄 How It Works

```
                                [ Incoming URL ]
         (Manual Entry | Clipboard Copy | Windows Notification | Browser Extension)
                                       │
                                       ▼
                   ┌───────────────────────────────────────┐
                   │    1. URL Parsing & Sanitization      │
                   │  - Reject malformed / credentials     │
                   │  - Strip sensitive query parameters   │
                   └───────────────────┬───────────────────┘
                                       │
                                       ▼
                   ┌───────────────────────────────────────┐
                   │  2. Instant Local Heuristics (Tier 1) │
                   │  - Authority '@' obfuscation check    │
                   │  - Brand lookalike boundary matching  │
                   │  - Multi-part ccTLD validation        │
                   │  - IP literal detection               │
                   └───────────────────┬───────────────────┘
                                       │
                         Calculates Risk & Flags
                                       │
                        ┌──────────────┴──────────────┐
                        ▼                             ▼
              [ Low / Medium / High ]       [ Save Sanitized URL ]
              Instant Analysis Result        (Local History: <=100)
                        │
                        ▼ (User Requests "Deep Research")
                   ┌───────────────────────────────────────┐
                   │ 3. On-Demand Network Probes (Tier 2)  │
                   │  - RDAP Domain Registration Check     │
                   │  - DNS-over-HTTPS (DoH Cloudflare)    │
                   │  - In-Band TLS & X.509 Certificate    │
                   │  - URLhaus Threat Feed Match          │
                   │  - SSRF-Safe Hop-by-Hop Redirects     │
                   └───────────────────┬───────────────────┘
                                       │
                                       ▼
                   ┌───────────────────────────────────────┐
                   │    4. Interactive Evidence Review     │
                   │  - Expandable finding cards           │
                   │  - Auto-expanded suspicious drawers   │
                   │  - Explicit warnings on failure       │
                   └───────────────────────────────────────┘
```

---

## 📁 Project Structure

```
LinkProtection/
├── browser-extension/            # Manifest V3 browser extension
│   ├── background.js             # Service worker intercepting navigation
│   ├── manifest.json             # Extension manifest & permissions
│   ├── popup.html / popup.js     # Extension popup interface
│   └── icons/                    # Extension icon assets
├── public/                       # Static public assets & brand icons
├── src/                          # Frontend application source
│   ├── components/               # Reusable UI components & navigation
│   ├── engines/                  # Authoritative JavaScript heuristic engines
│   │   ├── evidenceEngine.js     # Heuristic flag evaluator
│   │   ├── explanationEngine.js  # Human-readable risk explanations
│   │   ├── riskEngine.js         # Weighted scoring & risk level assignment
│   │   └── urlAnalyzer.js        # Strict URL parser & domain extraction
│   ├── notification/             # Floating alert & notification handlers
│   ├── pages/                    # Main views
│   │   ├── analyze.js            # Instant scan input & breakdown
│   │   ├── dashboard.js          # Main monitoring overview & quick stats
│   │   ├── deepResearch.js       # Expandable 5-module research drawers
│   │   ├── history.js            # Privacy-sanitized scan history table
│   │   └── settings.js           # Engine thresholds & integration toggles
│   ├── clipboardDetector.js      # Deduplicated clipboard monitoring logic
│   ├── extensionBridge.js        # Browser extension IPC communication bridge
│   ├── protectionState.js        # Global reactive protection state manager
│   ├── router.js                 # Lightweight single-page application router
│   ├── storage.js                # Sanitized LocalStorage wrapper (100-cap)
│   ├── style.css                 # Primary design system & CSS stylesheet
│   └── tauriBridge.js            # Tauri IPC command wrapper
├── src-tauri/                    # Native Rust backend
│   ├── src/
│   │   ├── deep_scan.rs          # Network probes: RDAP, DoH, TLS, URLhaus, Redirects
│   │   └── main.rs               # Tauri entrypoint, Win32 system tray, floating alerts
│   ├── Cargo.toml                # Rust dependencies & optimization profiles
│   └── tauri.conf.json           # Tauri v2 application configuration & CSP
├── scripts/                      # Build, packaging, and validation automation
│   ├── build-candidate-v2.ps1    # End-to-end frontend build and release executable compilation
│   ├── package-extension.js      # Clean ZIP packaging for browser extension
│   ├── run-all-js-tests.ps1      # Automated JavaScript test suite runner
│   └── validate-public-assets.js # Pre-build asset integrity and backup file scanner
├── server.js                     # Local loopback HTTP analysis server (port 27432)
├── package.json                  # Node.js project scripts & dependencies
└── vite.config.js                # Vite build and development configuration
```

---

## 🚀 Installation & Development

### Prerequisites
- **Node.js**: Version 18 or higher (LTS recommended)
- **Rust Toolchain**: Stable `rustc` and `cargo` (via [rustup](https://rustup.rs/))
- **Operating System**: Windows 10 or Windows 11 (64-bit)

### 1. Install Dependencies
```powershell
npm install
```

### 2. Frontend Development Mode
Run the Vite development server with hot-module replacement:
```powershell
npm run dev
```

### 3. Build Frontend Assets
Validate public assets and compile the production bundle to `dist/`:
```powershell
npm run build
```

### 4. Build the Native Desktop Application
Compile the release binary with Tauri custom protocol features:
```powershell
npm run build:backend
```
*Or execute the end-to-end build script:*
```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-candidate-v2.ps1
```

### 5. Package the Browser Extension
Generate a clean, allowlisted ZIP archive of the browser extension:
```powershell
npm run package:extension
```

### 6. Run the Companion Local Analysis Server
Start the local HTTP service on `127.0.0.1:27432` for browser extension integration:
```powershell
npm run server
```

---

## 🧪 Testing

BaitZero includes focused automated test suites covering URL parsing accuracy, heuristic boundary handling, clipboard safety, storage privacy, packaging safeguards, and expandable Deep Research cards.

To run individual test suites:

```powershell
# 1. Expandable Deep Research Finding Cards Suite (All 5 modules, ARIA states, URLhaus failure warnings)
node test-expandable-deep-research.js

# 2. Local URL Heuristic & Brand Boundary Accuracy Suite (At-symbol obfuscation, brand matching, ccTLDs)
node test-batch-a.js

# 3. Clipboard URL Detection & Deduplication Suite (Idle polling, password protection, sequence progression)
node test-clipboard.js

# 4. History Storage & Data Minimization Suite (100-record cap, query stripping, no token leaks)
node test-history-privacy.js

# 5. Context-Aware Floating Alert Positioning Suite (Mode A/B positioning, toast suppression, mascot render)
node test-context-aware-alerts.js

# 6. Windows Notification Extraction Suite (URL extraction, source badging, in-place update detection)
node test-notification.js

# 7. Asset & Extension Packaging Safeguards Suite (Backup detection, manifest schema validation)
node test-packaging-safeguards.js
```

### Verified Test Results
Every test suite has been executed and confirmed passing locally:
- **`test-expandable-deep-research.js`**: 5 test passes succeeded (100% pass rate)
- **`test-packaging-safeguards.js`**: 24 passed, 0 failed
- **`test-history-privacy.js`**: 39 passed, 0 failed
- **`test-batch-a.js`**: 33 passed, 0 failed
- **`test-clipboard.js`**: 51 passed, 0 failed
- **`test-context-aware-alerts.js`**: 26 passed, 0 failed
- **`test-notification.js`**: 52 passed, 0 failed

---

## 🔒 Privacy & Security Guarantees

- **Local-First Architecture**: URL heuristics and instant assessments execute entirely on your machine. No telemetry or navigation logs are dispatched to remote servers.
- **SSRF Prevention**: All network probes enforce strict private, loopback, link-local, multicast, and CGNAT IP filtering on both IPv4 and IPv6 to prevent Server-Side Request Forgery attacks.
- **Credential & Secret Protection**: URLs with embedded basic authentication (e.g., `user:pass@host`) are flagged or stripped. Raw passwords, authentication tokens, and query strings are excluded from storage.
- **Honest Status Reporting**: BaitZero never suppresses network errors or treats upstream failures as clean results. If a threat feed or DNS service is unavailable, users are clearly informed.

---

## ⚠️ Current Status & Limitations

- **Platform Target**: BaitZero is currently tailored for Windows desktop environments leveraging Win32 shell APIs and WebView2 / Tauri v2.
- **External Dependencies**: Deep Research modules require active internet connectivity and rely on the availability of third-party public infrastructure (`rdap.org`, Cloudflare DoH, and abuse.ch).
- **Heuristic Scope**: Heuristic risk scores reflect structural and contextual anomalies; sophisticated attackers may host malicious content on newly aged legitimate domains with valid TLS certificates. Users should exercise caution regardless of risk score.

---

## 🤝 Contributing

Contributions to improve BaitZero's detection capabilities, frontend performance, or documentation are welcome.

1. Fork the repository on GitHub.
2. Create a focused feature branch (`git checkout -b feature/improved-detection`).
3. Ensure all automated test suites pass cleanly (`node test-expandable-deep-research.js`, etc.).
4. Commit your changes with clear, descriptive commit messages.
5. Push to your branch and open a Pull Request.

---

## 📄 License

The license for this repository has not yet been specified. All rights are reserved by the project authors pending license selection.
