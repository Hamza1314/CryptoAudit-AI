CryptoAudit AI
AI-Powered Cryptographic Security Audit Platform

Detect. Analyze. Explain. Remediate.

CryptoAudit AI is an AI-powered Static Application Security Testing (SAST) platform focused on identifying cryptographic vulnerabilities, insecure coding practices, and security misconfigurations across source code. The platform combines a rule-based security engine with AI-generated risk analysis and remediation guidance to help developers and security teams build more secure applications.

Table of Contents
Overview
Features
Supported Languages
Security Audit Modules
Architecture
Detection Workflow
Dashboard
Example Findings
Technologies Used
Installation
Usage
Sample Report
Rule Coverage
Project Structure
Screenshots
Roadmap
Disclaimer
License
Overview

Modern software frequently contains cryptographic implementation mistakes that can lead to severe security vulnerabilities, including:

Credential compromise
Authentication bypass
Data leakage
Session hijacking
Man-in-the-Middle attacks
Broken encryption

CryptoAudit AI automatically scans source code repositories, identifies insecure cryptographic implementations, explains the security risks using AI, and provides practical remediation guidance following modern security best practices.

Features
Static Code Analysis
Rule-based security scanning
Multi-language support
Repository scanning
File-level analysis
Line-by-line evidence extraction
AI Security Analysis
AI-generated risk explanations
Human-readable remediation
Secure code recommendations
Context-aware vulnerability descriptions
Security Reporting
Markdown reports
JSON reports
Severity classification
CWE Mapping
Evidence snippets
AI remediation
Modern Dashboard
Interactive UI
Vulnerability explorer
Search findings
Security metrics
Export reports
Supported Languages

Currently supported

Python
Java
JavaScript
TypeScript
Go
C
C++
Environment files (.env)

Future support

Rust
PHP
C#
Kotlin
Swift
Security Audit Modules
1. Cryptographic Security Audit

Detects:

MD5
SHA-1
Weak password hashing
ECB Mode
DES
RC4
Weak RSA key sizes
Hardcoded encryption keys
Hardcoded secrets
Weak TLS
Insecure JWT configuration
Predictable random numbers
Deprecated crypto APIs
2. Secrets Detection

Detects:

AWS Keys
Azure Keys
GCP Keys
API Keys
Private Keys
Database passwords
JWT secrets
Environment secrets
3. Authentication Security Audit

Detects:

Weak password storage
JWT issues
Missing secure cookies
Authentication weaknesses
Authorization problems
4. Secure Coding Audit

Detects insecure coding practices including:

Injection risks
Insecure file handling
Dangerous API usage
Unsafe deserialization
Security misconfigurations
5. Dependency & Configuration Audit

Detects

Vulnerable packages
Weak TLS configuration
Insecure dependencies
Debug configurations
Security header issues
Architecture
                    Source Repository
                           │
                           ▼
                 Static File Discovery
                           │
                           ▼
                  Language Detection
                           │
                           ▼
                  Security Rule Engine
                           │
          ┌────────────────┴────────────────┐
          ▼                                 ▼
   Cryptographic Rules               Secret Detection
          ▼                                 ▼
   Authentication Rules            Configuration Rules
          └────────────────┬────────────────┘
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
Detection Workflow
Repository
    │
    ▼
Parse Source Files
    │
    ▼
Apply Security Rules
    │
    ▼
Collect Evidence
    │
    ▼
Classify Severity
    │
    ▼
Generate AI Analysis
    │
    ▼
Generate AI Remediation
    │
    ▼
Export Security Report
Dashboard

The dashboard provides:

Repository scanning
Security overview
Vulnerability explorer
AI-powered explanations
Evidence viewer
Search functionality
Markdown export
JSON export
Example Finding
CRYPTO-001

Finding
Weak Hashing Algorithm (MD5)

Severity
HIGH

File
auth.py

Line
42

Evidence
hashlib.md5(password.encode())

Risk
MD5 is cryptographically broken and susceptible to collision attacks.

Recommendation
Replace MD5 with SHA-256 for integrity verification.
For password hashing use Argon2id, bcrypt or scrypt.

CWE
CWE-328
Technologies Used
Backend
Python
FastAPI
Rule-based Security Engine
AI Integration
Frontend
HTML
CSS
JavaScript
AI
Local LLM / OpenAI Compatible Models
AI Risk Analysis
AI Remediation
Reports
Markdown
JSON
Installation
git clone https://github.com/yourusername/CryptoAuditAI.git

cd CryptoAuditAI

pip install -r requirements.txt

python main.py
Usage

Start the application

python main.py

Open your browser

http://localhost:8000

Upload a project or select a preloaded vulnerable application.

Run the desired security audit module.

Review findings and export the report in Markdown or JSON format.

Sample Report
Total Findings : 22

Critical : 7

High : 15

Medium : 0

Low : 0

Each finding includes

Vulnerability ID
Severity
CWE
Evidence
Risk Analysis
AI Explanation
Recommended Fix
Rule Coverage

Current rule coverage includes:

Weak hashing
Password storage
Hardcoded secrets
Weak symmetric encryption
ECB mode
DES / RC4 detection
TLS misconfiguration
JWT weaknesses
Random number generation
Certificate validation
Deprecated cryptographic APIs
Weak key sizes

The rule set will continue to expand as new cryptographic weaknesses and secure coding guidelines emerge.

Project Structure
CryptoAuditAI/
│
├── backend/
│   ├── scanner/
│   ├── rules/
│   ├── ai/
│   ├── reports/
│   └── api/
│
├── frontend/
│   ├── css/
│   ├── js/
│   ├── assets/
│   └── index.html
│
├── test-projects/
│
├── reports/
│
├── screenshots/
│
├── requirements.txt
│
└── README.md
Screenshots

Add screenshots demonstrating:

Dashboard
Scan progress
Vulnerability findings
AI remediation
Exported report
Future Roadmap
Repository cloning via Git URL
SARIF report export
CVE database integration
MITRE ATT&CK mapping
OWASP Top 10 mapping
Dependency vulnerability scanning
Docker image scanning
CI/CD integration
GitHub Actions support
VS Code extension
PDF report export
Multi-user authentication
Security score calculation
Why This Project?

CryptoAudit AI was built as a portfolio project to demonstrate practical skills in:

Secure Software Development
Static Application Security Testing (SAST)
Cryptography
Secure Coding
AI-assisted Security Analysis
Security Automation
Backend Development
Frontend Development
Vulnerability Reporting
Disclaimer

This project is intended for educational, research, and defensive security purposes only. It is designed to help developers identify and remediate cryptographic weaknesses in software they own or are authorized to assess. Always ensure you have permission before scanning third-party code.

License

This project is licensed under the MIT License. See the LICENSE file for details.

⭐ Support

If you found this project useful:

⭐ Star the repository
🐛 Report issues
💡 Suggest new security rules
🤝 Contribute improvements through pull requests