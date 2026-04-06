# 🛡️ VulnScan — Web Vulnerability Scanner

A Python-based CLI tool that scans websites for common security vulnerabilities.
Built as a portfolio project to demonstrate understanding of real attack vectors.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## ⚠️ Legal Disclaimer

This tool is for **authorized testing only**. Only scan websites you own
or have explicit written permission to test. Unauthorized scanning may
be illegal under PECA 2016 (Pakistan), CFAA (USA), and equivalent laws
in other countries.

---

## Features

- 🔍 **Security Headers** — detects missing CSP, HSTS, X-Frame-Options and more
- 🔌 **Port Scanner** — checks 13 commonly exposed ports
- 💉 **SQL Injection** — tests forms with error-based SQLi payloads
- ⚡ **XSS Detection** — tests forms for reflected XSS vulnerabilities
- 🧵 **Threading** — parallel scanning for faster results
- 📊 **HTML Report** — clean visual report with severity cards
- 📁 **JSON Output** — machine-readable output for pipelines

---

## Installation
```bash
git clone https://github.com/YOUR_USERNAME/web-vuln-scanner.git
cd web-vuln-scanner
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate

pip install -r requirements.txt
```

---

## Usage
```bash
# Basic scan
python scanner.py --url http://testphp.vulnweb.com

# Run in parallel (faster)
python scanner.py --url http://testphp.vulnweb.com --threads

# Scan specific modules only
python scanner.py --url http://testphp.vulnweb.com --scan headers ports

# Generate HTML report
python scanner.py --url http://testphp.vulnweb.com --output html

# Generate JSON report
python scanner.py --url http://testphp.vulnweb.com --output json
# See all options

<img width="885" height="830" alt="image" src="https://github.com/user-attachments/assets/7a154535-42a8-4cf9-848d-eab9a0ed6927" />

python scanner.py --help
```

---
