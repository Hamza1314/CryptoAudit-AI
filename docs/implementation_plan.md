# Implementation Plan - Cryptographic Security Audit Platform

A modern, comprehensive **Cryptographic Security Audit Platform** that statically scans source code repositories for cryptographic flaws, enriches findings using an AI explanation layer, and generates structured security audit reports.

---

## Architecture Overview

```
 ┌────────────────────────────────────────────────────────┐
 │            Target Application / Source Code            │
 └──────────────────────────┬─────────────────────────────┘
                            │
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │                 Static Scanner Engine                  │
 │   • Pattern/AST Scanners (Python, JS/TS, Java, Go, C) │
 └──────────────────────────┬─────────────────────────────┘
                            │
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │                      Rule Engine                       │
 │  • Hashes (MD5/SHA1)    • Password Storage (PBKDF2/Argon2)│
 │  • Secrets & Keys       • Cipher Modes (ECB vs CBC/GCM)  │
 │  • PRNGs (random vs secrets) • TLS & Cert Configs       │
 │  • JWT Algorithms       • Deprecated Crypto APIs        │
 └──────────────────────────┬─────────────────────────────┘
                            │
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │                 Local AI Layer (Enricher)              │
 │ • Contextual Risk Synthesis                            │
 │ • Automated Code Remediation Diffs                     │
 │ • CWE / NIST / OWASP Standards Mapping                 │
 └──────────────────────────┬─────────────────────────────┘
                            │
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │            Interactive Audit Dashboard & Report        │
 │  • File Explorer with Code Highlighted Evidence        │
 │  • Severity Distribution & Risk Scores                │
 │  • Printable/Exportable Audit Reports (JSON/HTML/MD)  │
 └────────────────────────────────────────────────────────┘
```

---

## User Review Required

> [!IMPORTANT]
> **Dual Interface Strategy**: I have  build both:
> 1. A standalone **CLI / Python Engine (`crypto_audit.py`)** that can be executed directly in the command line on any folder or repository.
> 2. A rich **Interactive Web Application Dashboard (HTML/CSS/JS with Vite/Node backend or single-page app)** allowing users to drag-and-drop code folders, select pre-configured test apps, run instant scans, view highlighted findings, and generate security reports.

---

## Key Features & Rules

1. **Detection Categories Covered**:
   - **Weak Hashing**: `MD5`, `SHA1` (MD5/SHA1 for checksums vs auth/signatures)
   - **Weak Password Storage**: Plain MD5/SHA256 without salt, weak iteration counts in PBKDF2/bcrypt.
   - **Hardcoded Secrets & Encryption Keys**: High-entropy strings, API tokens, AES static key bytes.
   - **Insecure Randomness**: `math.random()`, `random.randint()` used in security/crypto contexts instead of `crypto/secrets`.
   - **Weak Symmetric Ciphers & Modes**: `AES-ECB` mode, `DES`, `3DES`, `RC4`, key length < 128/256 bits.
   - **Deprecated APIs**: `Crypto.Cipher.XOR`, old OpenSSL bindings, deprecated Java `MessageDigest` patterns.
   - **TLS & Certificate Vulnerabilities**: `ssl._create_unverified_context()`, disabled SSL verification, TLS 1.0/1.1 usage.
   - **Insecure JWT Configurations**: `alg: "none"`, weak secret keys (< 32 chars), missing expiration validation.

2. **AI Analysis Layer**:
   - Analyzes code context around findings.
   - Computes realistic risk ratings (CRITICAL, HIGH, MEDIUM, LOW, INFO).
   - Generates exact line-by-line code remediation patches (diffs).
   - Maps vulnerabilities to CWE numbers (e.g., CWE-327, CWE-330, CWE-798, CWE-326) and NIST SP 800-131A standards.

3. **Pre-Loaded Demo Vulnerable Repositories**:
   - **Python Flask Auth Microservice**: Contains MD5 password hashing, hardcoded JWT secrets, and AES-ECB encryption.
   - **Node.js Express Payment Gateway**: Contains `Math.random()` token generation, `alg: "none"` JWT verification, and hardcoded RSA private key.
   - **Java Enterprise Utility**: Contains DES cipher instantiation, disabled SSL certificate checking, and weak RSA 1024-bit key pairs.

---


## Proposed Changes

### [Backend Component]
- `backend/crypto_audit.py`: Command-line executable accepting `--path`, `--format`, `--output`, `--ai-explain` flags.
- `backend/scanner/rules.py`: Structured definitions for all 8 required cryptographic vulnerability classes.
- `backend/scanner/ai_enricher.py`: Engine providing contextual risk explanation, CWE mapping, and suggested code replacement.
- `backend/test_samples/*`: Three complete, realistic target repositories for instant testing.

### [Frontend Component]
- `frontend/index.html`: Responsive, dark-mode cybersecurity dashboard with scanning animation, file browser, findings table, risk details panel, and export options.
- `frontend/css/styles.css`: Glassmorphic UI with severity badges (Critical, High, Medium, Low), code diff visualizer, and audit summary charts.
- `frontend/js/static_scanner.js`: Complete JavaScript implementation of the AST/regex static scanner engine that runs in-browser on dropped code directories or selected samples.

---

## Verification Plan

### Automated Verification
1. Run CLI static scanner against `backend/test_samples/python_auth_app/` and verify detection of SHA-1, hardcoded secrets, AES-ECB, and weak randomness.
2. Run CLI static scanner against `backend/test_samples/node_payment_service/` and verify detection of JWT `alg: "none"` and `Math.random()`.
3. Test JSON/Markdown export generation via `python backend/crypto_audit.py --path backend/test_samples/python_auth_app/ --output report.json`.

### Manual Verification
1. Launch the Web Application locally and inspect the interactive visual dashboard.
2. Select pre-loaded vulnerable apps in the UI and click "Run Audit".
3. Verify that findings render with: Finding ID, Severity badge, File line evidence, Risk summary, AI remediation suggestion, and CWE references.
4. Export the resulting audit report in HTML and Markdown formats.
