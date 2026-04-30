<div align="center">

# 🛡️ HeuristiX

**Web Security Scanner**

*Detect malware, phishing, and security threats*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Research-red.svg)](#legal--ethical-notice)

---

## 🎯 What HeuristiX Does

HeuristiX scans websites for security threats using heuristic analysis:

- 🔍 **Crawls Websites** - Visits pages and follows links
- 🦠 **Detects Malware** - Finds crypto miners, malicious scripts, and obfuscated code
- 🎣 **Identifies Phishing** - Spots fake login forms and brand impersonation
- 🔗 **Analyzes Links** - Checks for suspicious URLs and dangerous destinations
- 📊 **Scores Sites** - Provides a 0-100 safety score with detailed reports

---

## ✨ Features

### Detection Capabilities
- **Malware Detection** - ActiveX exploitation, crypto mining, dynamic code execution (eval), obfuscated payloads (Base64, hex, unicode), script injection patterns
- **Phishing Detection** - Suspicious TLD detection, form submits to IP addresses, password forms on untrusted domains, brand impersonation, cross-domain form actions
- **Link Analysis** - URL shortener detection, suspicious keywords, link mismatch indicators
- **Security Headers** - Checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- **Cookie Analysis** - Analyzes cookies for Secure, HttpOnly, and SameSite flags
- **CSP Analysis** - Parses and validates Content Security Policy directives
- **SSL/TLS Inspection** - Analyzes SSL certificates for security issues
- **DNS Analysis** - Analyzes DNS records for suspicious configurations
- **Technology Detection** - Identifies CMS, frameworks, and libraries in use
- **Redirect Analysis** - Analyzes HTTP redirects for loops and open redirects
- **Port Scanning** - Scans for open ports on target hosts
- **HTTP Method Testing** - Tests for unsafe methods (PUT, DELETE, TRACE) and CORS issues
- **CVE Checking** - Checks detected libraries for known vulnerabilities
- **Subdomain Enumeration** - Discovers subdomains via DNS bruteforce
- **Screenshot Capture** - Captures screenshots of websites for visual inspection

### Scanning Features
- **Multi-page Crawling** - Visits multiple pages with configurable depth
- **Googlebot Mode** - Uses Googlebot user agent to reveal hidden content
- **SSL Bypass** - Checks sites with broken certificates
- **Parallel Processing** - Crawls multiple pages simultaneously
- **CDN Whitelist** - Recognizes legitimate CDNs (GitHub, Google, Microsoft, etc.)
- **News Site Detection** - Reduces false positives on legitimate news sites

### Reporting
- **Risk Score (0-100)** - Higher score = safer
- **Severity Levels** - Critical, High, Medium, Low
- **JSON Export** - Raw scan data for analysis
- **HTML Report** - Formatted report in browser
- **PDF Export** - Professional PDF reports
- **Scan History** - Persistent history of previous scans

---

# 🐍 Installation

### Option A: Docker (Recommended for Security Isolation)

> **Why Docker?** HeuristiX downloads files from potentially malicious websites. Running in Docker ensures if a scanned site attempts to exploit the scanner, it only affects the isolated container - not your host system.

#### Prerequisites
- Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)

#### Quick Start
```bash
cd "C:\Users\Usuario\Desktop\HeuristiX"
docker-compose up --build
```

Open your browser to `http://127.0.0.1:5000`

Stop when done:
```bash
docker-compose down
```

#### Docker Security Features
- ✅ **Non-root user** - Limited permissions inside container
- ✅ **Read-only filesystem** - Prevents malware modification
- ✅ **Resource limits** - CPU and memory constraints
- ✅ **Dropped capabilities** - Minimal attack surface
- ✅ **No new privileges** - Cannot gain additional permissions

#### Manual Docker Build
```bash
docker build -t heuristix .
docker run -d -p 5000:5000 -v "$(pwd)/reports:/app/reports" --name heuristix-scanner heuristix
```

#### Ephemeral Mode (No Persistence)
```bash
docker run -d -p 5000:5000 --read-only --tmpfs /app/reports --name heuristix-scanner heuristix
```

---

### Option B: Local Python Installation

#### 1. Install Python
Download [Python 3.10+](https://www.python.org/downloads/) - **Check "Add Python to PATH"**

#### 2. Open Project Folder
```bash
cd "C:\Users\Usuario\Desktop\HeuristiX"
```

#### 3. Create Virtual Environment
```bash
python -m venv venv
```

#### 4. Activate Virtual Environment
- **PowerShell**: `.\venv\Scripts\Activate.ps1`
- **Command Prompt**: `venv\Scripts\activate.bat`
- **Linux/macOS**: `source venv/bin/activate`

#### 5. Install Dependencies
```bash
pip install -r requirements.txt
```

#### 6. Initialize Domain Database (One-Time)
```bash
python -c "import tldextract; tldextract.TLDExtract().extract('example.com')"
```

#### 7. Verify Installation
```bash
python -c "from scanner import FileAnalyzer; print('OK')"
```

---

## Usage

### Web Dashboard

**With Docker:**
```bash
docker-compose up --build
# Open http://127.0.0.1:5000
docker-compose down
```

**With Python:**
```bash
python app.py
# Open http://127.0.0.1:5000
```

### Command Line

```bash
# Basic scan
python cli.py example.com --pages 30 --depth 2 --format both

# Quick scan, JSON only
python cli.py example.com --pages 10 --depth 1 --format json

# Deep scan, HTML report
python cli.py example.com --pages 100 --depth 3 --format html

# Stealth mode (hide from site detection)
python cli.py example.com --stealth
```

---

## Understanding Results

### Risk Score
- 🟢 **71-100** - Safe, no major problems
- 🟡 **51-70** - Some suspicious patterns, be careful
- 🔴 **0-50** - Dangerous, do not trust

### Threat Severity
- 🔴 **Critical** - Known malware, active attacks
- 🟠 **High** - Phishing, credential stealing
- 🟡 **Medium** - Suspicious patterns
- 🟢 **Low** - Minor issues

---

## Project Structure

```
HeuristiX/
├── app.py                    # Web server
├── cli.py                    # Command-line tool
├── requirements.txt          # Dependencies
├── scanner/
│   ├── __init__.py
│   ├── crawler.py            # Website crawler
│   ├── analyzer.py           # Analysis engine
│   ├── detectors.py          # Threat detectors
│   ├── reporter.py           # Report generator
│   ├── cookie_analyzer.py    # Cookie security analysis
│   ├── csp_analyzer.py       # CSP validation
│   ├── ssl_inspector.py      # SSL/TLS inspection
│   ├── dns_analyzer.py       # DNS analysis
│   ├── tech_detector.py      # Technology detection
│   ├── redirect_analyzer.py  # Redirect analysis
│   ├── port_scanner.py       # Port scanning
│   ├── http_method_tester.py # HTTP method testing
│   ├── cve_checker.py        # CVE checking
│   ├── subdomain_enum.py     # Subdomain enumeration
│   └── screenshot.py         # Screenshot capture
├── templates/
│   └── index.html            # Web dashboard
└── reports/                  # Scan results
```

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'scanner'"
Run commands from the main folder, not inside `scanner/`

### "SyntaxError" or weird errors
Ensure Python 3.10+ is installed: `python --version`

### First scan is very slow
Run the domain database initialization (Step 6 above)

### Cannot reach a site that works in browser
HeuristiX uses Googlebot identity. Some sites block bots. Modify `scanner/crawler.py` if needed.

---

# 🌐 Chrome Extension

**For instant security checks while browsing**

## Features

- ⚡ **Instant Scanning** - Scan current page in 1-3 seconds
- 🎯 **Same Detection Logic** - Uses the same patterns as the Python version
- 🔒 **No External Dependencies** - Everything runs in your browser
- 📱 **Context Menu** - Right-click any page to scan
- 🌍 **No Internet Required** - All scanning happens locally
- 🔄 **Auto-Scan on Page Load** - Optional automatic scanning when you visit new sites
- 📜 **Scan History** - View your last 20 scans with scores and verdicts
- 📥 **Export Results** - Download scan results as JSON for analysis
- 📁 **File Scanning** - Upload and scan individual files for malware
- 🛡️ **Safety Badge** - Real-time score displayed on extension icon
- 🚫 **Site Blocking** - Block dangerous sites (score ≤ 50) automatically
- 🎓 **Phishing Training** - Interactive quiz to improve phishing awareness

## Detection Capabilities

### Malware Detection
- ActiveX exploitation attempts
- Cryptocurrency mining scripts
- Dynamic code execution (eval)
- Obfuscated payloads (Base64, hex, unicode)
- Script injection patterns
- Known malicious domain references
- External executable file links
- WebAssembly detection
- Command execution attempts

### Phishing Detection
- Suspicious TLD detection (.tk, .ml, .ga, etc.)
- Form submits to IP addresses
- Password forms on untrusted domains
- Brand impersonation detection
- Cross-domain form actions

### Link Analysis
- URL shortener detection
- Suspicious keyword detection
- Link mismatch / phishing indicators

### Privacy & Security
- Secret detection (API keys, tokens, passwords)
- Browser fingerprinting detection
- WebRTC IP leak detection
- Storage inspection (localStorage, sessionStorage, IndexedDB)
- Cookie manipulation detection
- Keylogger detection

## Installation

### Step 1: Generate Icons

```bash
cd "C:\Users\Usuario\Desktop\HeuristiX Browser Extension"
pip install pillow svglib
python generate_icons.py
```

### Step 2: Load Extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select: `C:\Users\Usuario\Desktop\HeuristiX Browser Extension`

### Optional: Package as .CRX

1. Open `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Pack extension**
4. Select the extension folder
5. Drag the resulting `.crx` into Chrome to install

## Usage

1. Navigate to any website
2. Click the HeuristiX extension icon (🛡️)
3. Click **"Scan Site"**
4. View the security score, verdict, and threats

## Risk Scoring

- 🟢 **71-100** - Safe - No major threats
- 🟡 **51-70** - Moderate Risk - Some suspicious patterns
- 🟠 **26-50** - High Risk - Multiple threats
- 🔴 **1-25** - Very Dangerous - Severe threats
- ⚫ **0** - Dangerous Phishing Site

## Differences from Python Version

The Chrome extension:
- Scans **only the current page** (not multi-page crawling)
- Analyzes **inline scripts only** (external scripts blocked by CORS)
- Runs **entirely in the browser** (no external dependencies)
- Is **faster for single-page scans** (no network overhead)

For full multi-page crawling and external script analysis, use the Python version with Docker isolation.

## Troubleshooting

### Icons not showing
Run `python generate_icons.py` to create PNG icons

### Scan fails with "Failed to get page content"
Refresh the page and try again. Some pages block content script injection.

### Extension not loading
Check Chrome console for errors at `chrome://extensions/`

---

## License

MIT License – use responsibly and ethically.

---

<div align="center">

**Made with 🔒 for a safer web**

[⬆ Back to Top](#-heuristix)

</div>
