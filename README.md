# CryptoAudit AI
## AI-Powered Cryptographic Security Audit Platform

### Detect. Analyze. Explain. Remediate.

**CryptoAudit AI** is a static analysis platform that scans source code repositories for cryptographic weaknesses, enriches every finding with AI-generated risk context and remediation code, and produces clean, exportable security audit reports.

It ships as **two interfaces**:
- 🖥️ A standalone **CLI engine** (`crypto_audit.py`) for scanning any folder or repo from the terminal.
- 🌐 An **interactive web dashboard** for drag-and-drop scanning, visual findings review, and one-click report export.

![Security Score](https://img.shields.io/badge/Security%20Score-Dynamic-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Python](https://img.shields.io/badge/Python-3.9%2B-yellow)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![FastAPI](https://img.shields.io/badge/FastAPI-Latest-green)
![AI Powered](https://img.shields.io/badge/AI-Powered-purple)
![Status](https://img.shields.io/badge/Status-Active-success)


# 📸 Dashboard Preview





## 📖 Overview

Modern software frequently contains cryptographic implementation mistakes that can lead to severe security vulnerabilities, including:
- 🔑 Credential compromise
- 🚪 Authentication bypass
- 📉 Data leakage
- 🕵️ Session hijacking
- 🕸️ Man-in-the-Middle (MitM) attacks
- 🔓 Broken encryption

---

## ✨ Features

### 🔍 Static Code Analysis
- Rule-based security scanning
- Multi-language support
- Repository & file-level analysis
- Line-by-line evidence extraction

### 🤖 AI Security Analysis
- AI-generated risk explanations
- Human-readable remediation
- Secure code recommendations
- Context-aware vulnerability descriptions

### 📊 Security Reporting
- Markdown & JSON reports
- Severity classification & CWE Mapping
- Evidence snippets
- AI remediation integration

### 🖥️ Modern Dashboard
- Interactive UI & Vulnerability explorer
- Search findings & Security metrics
- Export reports (Markdown/JSON)

---

## 💻 Supported Languages

**Currently Supported:**
`Python` | `Java` | `JavaScript` | `TypeScript` | `Go` | `C` | `C++` | `.env` files

**Future Support:**
`Rust` | `PHP` | `C#` | `Kotlin` | `Swift`

---

## 🧩 Security Audit Modules

1. **Cryptographic Security Audit**
   - Detects: MD5, SHA-1, Weak password hashing, ECB Mode, DES, RC4, Weak RSA key sizes, Hardcoded encryption keys/secrets, Weak TLS, Insecure JWT, Predictable random numbers, Deprecated crypto APIs.
2. **Secrets Detection**
   - Detects: AWS/Azure/GCP Keys, API Keys, Private Keys, Database passwords, JWT secrets, Environment secrets.
3. **Authentication Security Audit**
   - Detects: Weak password storage, JWT issues, Missing secure cookies, Auth weaknesses, Authorization problems.
4. **Secure Coding Audit**
   - Detects: Injection risks, Insecure file handling, Dangerous API usage, Unsafe deserialization, Security misconfigurations.
5. **Dependency & Configuration Audit**
   - Detects: Vulnerable packages, Weak TLS config, Insecure dependencies, Debug configurations, Security header issues.

---

## 🏗️ Architecture

```text
Source Repository
       ▼
Static File Discovery
       ▼
Language Detection
       ▼
Security Rule Engine ──────┬──── Cryptographic Rules
                           ├──── Secret Detection
                           ├──── Authentication Rules
                           └──── Configuration Rules
       ▼
Vulnerability Engine
       ▼
AI Risk Analysis
       ▼
AI Remediation Engine
       ▼
Report Generation Engine
       ▼
Markdown | JSON | Dashboard Output
```


# 🔄 Detection Workflow
Repository ➔ Parse Source Files ➔ Apply Security Rules ➔ Collect Evidence 
      ➔ Classify Severity ➔ Generate AI Analysis ➔ Generate AI Remediation 
      ➔ Export Security Report

      

# 🛠️ Technologies Used
Backend: Python, FastAPI, Rule-based Security Engine
Frontend: HTML, CSS, JavaScript
AI: Local LLM / OpenAI Compatible Models (Risk Analysis & Remediation)
Reports: Markdown, JSON



# 🚀 Installation

git clone https://github.com/Hamza1314/CryptoAudit-AI.git
cd CryptoAuditAI
pip install -r requirements.txt


# 🏃 Usage
 1.Start the application
      python -m http.server 8000

 2.Open your browser:
    Navigate to http://localhost:8000
    
 3.Scan:
    Upload a project or select a preloaded vulnerable application.
    
 4.Audit:
    Run the desired security audit module.
 5.Review & Export:
    Review findings and export the report in Markdown or JSON format.


# 📏 Rule Coverage
```text
Current rule coverage includes:

  Weak hashing & Password storage
  Hardcoded secrets & Weak symmetric encryption
  ECB mode & DES/RC4 detection
  TLS misconfiguration & JWT weaknesses
  Random number generation & Certificate validation
  Deprecated cryptographic APIs & Weak key sizes

The rule set will continue to expand as new cryptographic weaknesses and secure coding guidelines emerge.
```


# 📂 Project Structure

```text

CryptoAuditAI/
├── Project.md                 # Existing project specification
├── Project.txt                # Existing file
├── backend/                   # CLI & Core Engine
│   ├── crypto_audit.py        # CLI scanner tool
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── engine.py          # Core static analysis orchestrator
│   │   ├── rules.py           # Rule definitions & regex/AST checks
│   │   ├── ai_enricher.py     # AI risk & remediation synthesizer
│   │   └── reporter.py        # Report generation (Markdown/HTML/JSON)
├── test_samples/              # Controlled vulnerable application repos
│   ├── python_auth_app/
│   ├── node_payment_service/
│   └── java_crypto_module/
├── frontend/                  # Web Dashboard UI
│   ├── index.html             # Main UI Entrypoint
│   ├── css/styles.css         # Cyber-themed UI design system
│   └── js/
│       ├── app.js             # App controller & router
│       ├── static_scanner.js  # Client-side web worker scanning engine
│       ├── rules_db.js        # Client-side rule database
│       ├── ai_explainer.js    # Interactive AI remediation generator
│       └── report_builder.js  # Audit report rendering & exporter


```



# 🗺️ Future Roadmap

     Repository cloning via Git URL
     SARIF report export
     CVE database integration
     MITRE ATT&CK & OWASP Top 10 mapping
     Dependency & Docker image vulnerability scanning
     CI/CD integration & GitHub Actions support
     VS Code extension
     PDF report export
     Multi-user authentication
     Security score calculation



# 💡 Why This Project?

CryptoAudit AI was built as a portfolio project to demonstrate practical skills in:

     Secure Software Development & Secure Coding
     Static Application Security Testing (SAST)
     Cryptography & Security Automation
     AI-assisted Security Analysis
     Backend & Frontend Development
     Vulnerability Reporting


# ⚠️ Disclaimer

This project is intended for educational, research, and defensive security purposes only. It is designed to help developers identify and
remediate cryptographic weaknesses in software they own or are authorized to assess. 
Always ensure you have permission before scanning third-party code.


# ⚖️ License

This project is licensed under the MIT License. See the LICENSE file for details.

# ⭐ Support

If you found this project useful:
⭐ Star the repository
🐛 Report issues
💡 Suggest new security rules
🤝 Contribute improvements through pull requests

