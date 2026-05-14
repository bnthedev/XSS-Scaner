# XSS Scanner
 
> **For educational purposes only.** Only use on systems you own or have explicit written permission to test.
 
A cross-platform GUI tool for detecting XSS (Cross-Site Scripting) vulnerabilities. Built with Python and Tkinter, with optional Playwright integration for real browser-based testing that catches DOM-based and Stored XSS that traditional HTTP scanners miss.
 
![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Playwright](https://img.shields.io/badge/Playwright-optional-purple?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-Educational-red?style=flat-square)
 
---
 
## Features
 
| Feature | Requests mode | Playwright mode |
|---|---|---|
| Reflected XSS (URL params) | ✅ | ✅ |
| Reflected XSS (forms) | ✅ | ✅ |
| DOM-based XSS | ❌ | ✅ |
| Stored XSS detection | ✅ | ✅ |
| JS-rendered page crawling | ❌ | ✅ |
| Header injection testing | ✅ | ❌ |
| Custom payload list (.txt) | ✅ | ✅ |
| Multi-language UI (CS/EN/RU) | ✅ | ✅ |
| Cookie / Auth header support | ✅ | ✅ |
| JSON export | ✅ | ✅ |
 
### Scan modes
 
**Requests mode** — Fast, lightweight. Sends HTTP requests directly and checks responses for reflected payloads. Good for simple sites and quick reconnaissance.
 
**Playwright mode** — Launches a real browser (Chromium, Firefox, or WebKit) and listens for actual `alert()` dialogs. Catches vulnerabilities that only execute in a browser context. Slower but significantly more thorough.
 
### Stored XSS detection
 
Works in two phases:
1. **Phase 1** — For every tested input, a unique marker (`xss-probe-<id>`) is submitted alongside each payload. If the payload reflects immediately → Reflected XSS reported.
2. **Phase 2** — After the full scan, the crawler revisits all pages and searches for markers in the HTML. If a marker appears on a *different* page than where it was submitted → **Stored XSS detected**.
### JS crawling (Playwright only)
 
Uses `networkidle` wait strategy to crawl pages after JavaScript has fully rendered. Discovers links added dynamically by React, Vue, Angular, and other SPA frameworks that a standard HTTP crawler would miss entirely.
 
---
 
## Installation
 
### Requirements
 
- Python 3.8+
- pip
### Install dependencies
 
```bash
pip install requests beautifulsoup4
```
 
### Optional: Playwright (for browser-based testing)
 
```bash
pip install playwright
python -m playwright install chromium
```
 
To install all browsers:
```bash
python -m playwright install
```
 
---
 
## Usage
 
```bash
python xss_scanner.py
```
 
### Basic workflow
 
1. Enter the target URL in the **Target** field
2. Configure scan options (crawl, forms, params, headers)
3. Choose scan mode: **Requests** (fast) or **Playwright** (thorough)
4. Optionally add cookies or Authorization header for authenticated scans
5. Click **Start Scan**
6. Monitor results in the **Live log** and **Vulnerabilities** tabs
7. Export findings to JSON
### Custom payloads
 
Click **📂 Load payloads (.txt)** to load your own payload list. The file format is:
 
```
# This is a comment — ignored
<script>alert('custom')</script>
<img src=x onerror=alert(1)>
 
# DOM-based payloads
'-alert(1)-'
\"><svg/onload=alert(1)>
```
 
Rules:
- One payload per line
- Lines starting with `#` are comments
- Empty lines are ignored
- Custom payloads are **appended** to the built-in list (no duplicates)
---
 
## Project structure
 
```
xss-scanner/
├── xss_scanner.py       # Main application
└── lang/
    ├── cs.json          # Czech translations
    ├── en.json          # English translations
    └── ru.json          # Russian translations
```
 
---
 
## Understanding the results
 
| Severity | Meaning |
|---|---|
| **HIGH** | Script-tag based payload executed (`<script>alert(...)`) |
| **MEDIUM** | Event-handler based payload (`onerror`, `onload`, etc.) |
 
| Type suffix | Meaning |
|---|---|
| *(none)* | Reflected XSS detected via HTTP response |
| `[Browser]` | Confirmed by real `alert()` dialog in Playwright |
| `[Stored]` | Marker found on a different page than where it was submitted |
| `[Stored-Browser]` | Stored XSS confirmed via Playwright DOM inspection |
| `Form-Browser` | Form-based XSS confirmed in browser |
 
---
 
## Limitations
 
This tool is designed for **reflected and stored XSS** in standard HTML forms and URL parameters. It will **not** detect:
 
- Blind XSS (payload executes in an admin panel not visited during scan)
- XSS behind login without providing valid session cookies
- Vulnerabilities blocked by WAF (Web Application Firewall)
- CSP-protected pages where `alert()` is blocked but XSS still exists
- WebSocket or `postMessage`-based XSS vectors
---
 
## Disclaimer
 
This tool is provided for **educational and authorized security testing purposes only**.
 
- Do not use this tool against any system without explicit written permission from the owner
- Unauthorized security testing is illegal in most jurisdictions
- The author assumes no liability for misuse
---
 
*by bnthedev*
