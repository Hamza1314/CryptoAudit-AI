/**
 * Main Web Audit Application Controller
 */

// Demo Target Applications pre-loaded into the browser
const DEMO_SAMPLES = {
  python_auth_vulnerable: {
    name: "Python Flask Auth (Vulnerable Demo)",
    files: [
      {
        name: "auth.py",
        content: `import hashlib
import random
import jwt
from Crypto.Cipher import AES

SECRET_KEY = "super_secret_jwt_key_12345"

def hash_password(password):
    // CRYPTO-001 & CRYPTO-002: Weak MD5 hashing for passwords
    return hashlib.md5(password.encode()).hexdigest()

def verify_token(token):
    // CRYPTO-010: Insecure JWT validation allowing 'none' algorithm
    return jwt.decode(token, options={"verify_signature": False})

def generate_session_token():
    // CRYPTO-004: Insecure Math/Random PRNG for token generation
    return str(random.randint(100000, 999999))

def encrypt_user_data(data):
    // CRYPTO-005: ECB mode symmetric encryption & CRYPTO-008 hardcoded key
    key = b"1234567890123456"
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data.zfill(16).encode())`
      },
      {
        name: "crypto_utils.py",
        content: `import requests
import ssl
import hashlib

// CRYPTO-003: Hardcoded Private Key
PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\\n-----END PRIVATE KEY-----"

def fetch_remote_config():
    // CRYPTO-009: TLS certificate verification explicitly disabled
    response = requests.get("https://internal-api.local/config", verify=False)
    return response.json()

def get_insecure_context():
    // CRYPTO-009: Unverified SSL context
    return ssl._create_unverified_context()

def compute_checksum(data):
    // CRYPTO-001: Deprecated SHA1 usage
    return hashlib.sha1(data.encode()).hexdigest()`
      }
    ]
  },
  python_auth_remediated: {
    name: "Python Flask Auth (Remediated / 100% Secure)",
    files: [
      {
        name: "auth.py",
        content: `import os
import secrets
import hashlib
import jwt
from Crypto.Cipher import AES

SECRET_KEY = os.environ.get("APP_SECRET_KEY", "default_secure_secret_key_32bytes_long")

def hash_password(password):
    # Remediated: Secure password hashing using PBKDF2-HMAC-SHA256 with 600,000 iterations
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600000)
    return salt.hex() + ":" + key.hex()

def verify_token(token):
    # Remediated: Enforce JWT signature verification with explicit HS256 algorithm
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

def generate_session_token():
    # Remediated: Use CSPRNG secrets module for random numbers
    return str(secrets.randbelow(900000) + 100000)

def encrypt_user_data(data):
    # Remediated: AES-GCM mode with random nonce and secure key
    key = os.urandom(32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return cipher.nonce + tag + ciphertext`
      },
      {
        name: "crypto_utils.py",
        content: `import os
import requests
import ssl
import hashlib

# Remediated: Load secret / key dynamically from environment
PRIVATE_KEY = os.environ.get("PRIVATE_KEY_PATH")

def fetch_remote_config():
    # Remediated: TLS certificate verification enabled
    response = requests.get("https://internal-api.local/config", verify=True)
    return response.json()

def get_insecure_context():
    # Remediated: Standard default verified SSL context
    return ssl.create_default_context()

def compute_checksum(data):
    # Remediated: Use strong SHA-256 hash algorithm
    return hashlib.sha256(data.encode('utf-8')).hexdigest()`
      }
    ]
  },
  node_payment: {
    name: "Node.js Express Payment Gateway",
    files: [
      {
        name: "server.js",
        content: `const crypto = require('crypto');
const https = require('https');

// CRYPTO-003: Hardcoded API Key secret
const API_KEY = "sk_live_9923849283948293842938492";

function generatePaymentToken() {
    // CRYPTO-004: Insecure Math.random() for payment token
    return 'PAY-' + Math.random().toString(36).substring(2);
}

function legacyEncrypt(data) {
    // CRYPTO-006: Legacy weak DES cipher
    const cipher = crypto.createCipheriv('des-ecb', '12345678', '');
    return cipher.update(data, 'utf8', 'hex');
}

function sendPaymentPayload() {
    // CRYPTO-009: Reject unauthorized set to false
    const agent = new https.Agent({ rejectUnauthorized: false });
    console.log("Sending payment payload via insecure TLS agent...");
}`
      },
      {
        name: "jwt_handler.js",
        content: `const jwt = require('jsonwebtoken');

const JWT_SECRET = "my_hardcoded_jwt_secret_key";

function createUnsignedToken(payload) {
    // CRYPTO-010: Insecure JWT alg 'none'
    return jwt.sign(payload, null, { algorithm: 'none' });
}

function hashUserMD5(username) {
    // CRYPTO-001: MD5 hash creation in Node.js
    return crypto.createHash('md5').update(username).digest('hex');
}`
      }
    ]
  },
  java_crypto: {
    name: "Java Enterprise Crypto Utility",
    files: [
      {
        name: "LegacyCrypto.java",
        content: `package com.legacy.security;

import java.security.MessageDigest;
import java.security.KeyPairGenerator;
import java.util.Random;
import javax.crypto.Cipher;

public class LegacyCrypto {

    public static byte[] hashMD5(String input) throws Exception {
        // CRYPTO-001: MD5 MessageDigest in Java
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(input.getBytes());
    }

    public static byte[] encryptDES(byte[] data) throws Exception {
        // CRYPTO-005 & CRYPTO-006: DES in ECB mode
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        return cipher.doFinal(data);
    }

    public static void generateWeakRSAKey() throws Exception {
        // CRYPTO-006: Weak RSA key size 1024 bits
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        keyGen.generateKeyPair();
    }

    public int generateOTP() {
        // CRYPTO-004: java.util.Random non-cryptographic PRNG
        Random rand = new Random();
        return rand.nextInt(900000) + 100000;
    }
}`
      }
    ]
  }
};

class AppController {
  constructor() {
    this.scanner = new ClientStaticScanner();
    this.explainer = new ClientAIExplainer();
    this.reporter = new ClientReportBuilder();
    
    this.currentTargetName = DEMO_SAMPLES.python_auth_remediated.name;
    this.currentFiles = DEMO_SAMPLES.python_auth_remediated.files;
    this.findings = [];
    this.selectedFinding = null;

    this.initDOM();
    this.runScan();
  }

  initDOM() {
    this.scanBtn = document.getElementById("scan-btn");
    this.exportMdBtn = document.getElementById("export-md-btn");
    this.exportJsonBtn = document.getElementById("export-json-btn");
    this.searchInput = document.getElementById("search-input");
    this.findingsListEl = document.getElementById("findings-list");
    this.detailPanelEl = document.getElementById("detail-panel");
    this.dropzone = document.getElementById("dropzone");
    this.fileInput = document.getElementById("file-input");

    // Event Listeners
    if (this.scanBtn) this.scanBtn.addEventListener("click", () => this.runScan());
    if (this.exportMdBtn) this.exportMdBtn.addEventListener("click", () => this.reporter.exportMarkdown(this.findings, this.currentTargetName));
    if (this.exportJsonBtn) this.exportJsonBtn.addEventListener("click", () => this.reporter.exportJSON(this.findings, this.currentTargetName));
    if (this.searchInput) this.searchInput.addEventListener("input", () => this.renderFindingsList());

    // Sample buttons
    document.querySelectorAll(".sample-btn").forEach(btn => {
      btn.addEventListener("click", (e) => {
        document.querySelectorAll(".sample-btn").forEach(b => b.classList.remove("active"));
        e.currentTarget.classList.add("active");
        
        const sampleKey = e.currentTarget.getAttribute("data-sample");
        if (DEMO_SAMPLES[sampleKey]) {
          this.currentTargetName = DEMO_SAMPLES[sampleKey].name;
          this.currentFiles = DEMO_SAMPLES[sampleKey].files;
          this.runScan();
        }
      });
    });

    // Dropzone upload
    if (this.dropzone) {
      this.dropzone.addEventListener("click", () => this.fileInput.click());
      this.dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        this.dropzone.classList.add("dragover");
      });
      this.dropzone.addEventListener("dragleave", () => this.dropzone.classList.remove("dragover"));
      this.dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        this.dropzone.classList.remove("dragover");
        if (e.dataTransfer.files.length) {
          this.handleUploadedFiles(e.dataTransfer.files);
        }
      });
    }

    if (this.fileInput) {
      this.fileInput.addEventListener("change", (e) => {
        if (e.target.files.length) {
          this.handleUploadedFiles(e.target.files);
        }
      });
    }
  }

  handleUploadedFiles(files) {
    const fileList = [];
    const promises = Array.from(files).map(file => {
      return new Promise(resolve => {
        const reader = new FileReader();
        reader.onload = (e) => {
          fileList.push({ name: file.name, content: e.target.result });
          resolve();
        };
        reader.readAsText(file);
      });
    });

    Promise.all(promises).then(() => {
      this.currentTargetName = `Uploaded Repository (${fileList.length} files)`;
      this.currentFiles = fileList;
      this.runScan();
    });
  }

  runScan() {
    this.findingsListEl.innerHTML = `<div class="empty-state"><div class="spinner"></div><p>Executing Cryptographic Static Scanner & AI Analysis Layer...</p></div>`;

    setTimeout(() => {
      const raw = this.scanner.scanFileList(this.currentFiles);
      this.findings = raw.map(f => this.explainer.enrichFinding(f));
      
      this.renderMetrics();
      this.renderFindingsList();

      if (this.findings.length > 0) {
        this.selectFinding(this.findings[0]);
      } else {
        this.detailPanelEl.innerHTML = `<div class="empty-state" style="padding: 3rem 1rem;"><p style="font-size: 1.25rem; font-weight:700; color:var(--diff-add-text); margin-bottom: 0.5rem;">🎉 Security Audit Passed!</p><p style="color:var(--text-muted); font-size:0.875rem;">No Cryptographic Vulnerabilities Detected in Target Repository (100/100 Health Score).</p></div>`;
      }
    }, 300);
  }

  renderMetrics() {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    this.findings.forEach(f => {
      const sev = (f.severity || "MEDIUM").toUpperCase();
      counts[sev] = (counts[sev] || 0) + 1;
    });

    // Score calculation
    let penalty = (counts.CRITICAL * 30) + (counts.HIGH * 15) + (counts.MEDIUM * 5);
    let healthScore = Math.max(0, 100 - penalty);

    document.getElementById("score-value").innerText = `${healthScore}/100`;
    document.getElementById("total-findings").innerText = this.findings.length;
    document.getElementById("cnt-critical").innerText = counts.CRITICAL;
    document.getElementById("cnt-high").innerText = counts.HIGH;
    document.getElementById("cnt-medium").innerText = counts.MEDIUM;
  }

  renderFindingsList() {
    const query = (this.searchInput ? this.searchInput.value : "").toLowerCase();
    const filtered = this.findings.filter(f => 
      f.rule_name.toLowerCase().includes(query) ||
      f.rule_id.toLowerCase().includes(query) ||
      f.file.toLowerCase().includes(query) ||
      f.severity.toLowerCase().includes(query)
    );

    if (filtered.length === 0) {
      this.findingsListEl.innerHTML = `<div class="empty-state"><p>No matching findings found.</p></div>`;
      return;
    }

    this.findingsListEl.innerHTML = filtered.map((f, i) => {
      const isSelected = this.selectedFinding === f ? "border-color: var(--accent-indigo); background: var(--bg-card-hover);" : "";
      const sevClass = `badge-${f.severity.toLowerCase()}`;
      return `
        <div class="finding-item" style="${isSelected}" onclick="app.selectFindingByIndex(${i})">
          <div class="finding-item-header">
            <div>
              <span class="badge ${sevClass}">${f.severity}</span>
              <span style="font-size: 0.8rem; margin-left: 0.5rem; color: var(--text-muted); font-family: var(--font-mono);">${f.rule_id}</span>
              <div class="finding-title" style="margin-top: 0.3rem;">${f.rule_name}</div>
            </div>
          </div>
          <div class="finding-meta">
            <span>📁 File: <span class="finding-file">${f.file}:${f.line}</span></span>
            <span>🏷️ ${f.cwe || 'CWE'}</span>
          </div>
        </div>
      `;
    }).join("");
  }

  selectFindingByIndex(index) {
    if (this.findings[index]) {
      this.selectFinding(this.findings[index]);
    }
  }

  selectFinding(finding) {
    this.selectedFinding = finding;
    this.renderFindingsList();

    const patch = finding.remediation_patch || {};
    const refs = finding.references || [];

    this.detailPanelEl.innerHTML = `
      <div>
        <div style="display: flex; gap: 0.75rem; align-items: center; margin-bottom: 0.5rem;">
          <span class="badge badge-${finding.severity.toLowerCase()}">${finding.severity}</span>
          <span style="font-family: var(--font-mono); color: var(--accent-cyan); font-weight: 600;">${finding.rule_id}</span>
          <span style="color: var(--text-muted); font-size: 0.875rem;">${finding.cwe || ''}</span>
        </div>
        <h2 style="font-size: 1.25rem; font-weight: 700; color: var(--text-main);">${finding.rule_name}</h2>
      </div>

      <div>
        <div class="section-subtitle">📍 Location & Evidence</div>
        <div style="font-family: var(--font-mono); font-size: 0.8125rem; color: var(--accent-cyan); margin-bottom: 0.4rem;">
          ${finding.file} : Line ${finding.line}
        </div>
        <div class="code-block">${this.escapeHTML(finding.evidence)}</div>
      </div>

      <div>
        <div class="section-subtitle">🤖 AI Risk Context Analysis</div>
        <p style="color: var(--text-main); font-size: 0.875rem; line-height: 1.6; background: rgba(99, 102, 241, 0.06); border-left: 3px solid var(--accent-indigo); padding: 0.75rem 1rem; border-radius: 0 0.5rem 0.5rem 0;">
          ${finding.ai_risk_explanation || finding.description}
        </p>
      </div>

      <div>
        <div class="section-subtitle">🛠️ Recommended Remediation Code Fix</div>
        <div class="diff-box">
          <div class="diff-line-del">- ${this.escapeHTML(patch.before || finding.evidence)}</div>
          <div class="diff-line-add">+ ${this.escapeHTML(patch.after || finding.remediation)}</div>
        </div>
      </div>

      ${refs.length ? `
        <div>
          <div class="section-subtitle">📚 Security Standards & References</div>
          <ul style="padding-left: 1.25rem; font-size: 0.8125rem; color: var(--text-muted);">
            ${refs.map(r => `<li><a href="${r}" target="_blank" style="color: var(--accent-cyan);">${r}</a></li>`).join("")}
          </ul>
        </div>
      ` : ''}
    `;
  }

  escapeHTML(str) {
    return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
}

let app;
window.addEventListener("DOMContentLoaded", () => {
  app = new AppController();
});
