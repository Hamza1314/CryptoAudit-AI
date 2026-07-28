/**
 * Client-Side Cryptographic Rule Database
 */

const CRYPTO_RULES = [
  {
    id: "CRYPTO-001",
    name: "Weak Hashing Algorithm (MD5 / SHA-1)",
    category: "Weak Hashing Algorithms",
    severity: "HIGH",
    cwe: "CWE-328",
    patterns: [
      /hashlib\.(md5|sha1)\s*\(/i,
      /Crypto\.Hash\.(MD5|SHA1)/i,
      /crypto\.createHash\(\s*['"](md5|sha1)['"]\s*\)/i,
      /MessageDigest\.getInstance\(\s*['"](MD5|SHA-1|SHA1)['"]\s*\)/i,
      /crypto\/md5|crypto\/sha1/i
    ],
    description: "MD5 or SHA-1 detected. These hash functions suffer from cryptographically proven collision attacks.",
    remediation: "Use SHA-256 or SHA-3 for checksums, and Argon2id or bcrypt for credentials.",
    references: ["https://cwe.mitre.org/data/definitions/328.html"]
  },
  {
    id: "CRYPTO-002",
    name: "Weak Password Storage Pattern",
    category: "Weak Password Storage",
    severity: "CRITICAL",
    cwe: "CWE-916",
    patterns: [
      /password.*hashlib\.(md5|sha1|sha256)\(/i,
      /hashlib\.(md5|sha1|sha256)\(.*\bpassword/i,
      /pbkdf2.*iterations\s*=\s*([1-9][0-9]{0,3}|[1-9][0-9]{4})\b/i,
      /createHash\([^)]+\).*\bpassword/i,
      /MessageDigest\.getInstance\([^)]+\).*\bpassword/i
    ],
    description: "General fast hashing algorithm or insufficient PBKDF2 iterations used for storing passwords.",
    remediation: "Use Argon2id, bcrypt (cost >= 12), or PBKDF2-HMAC-SHA256 with 600,000+ iterations.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"]
  },
  {
    id: "CRYPTO-003",
    name: "Hardcoded Secret / Private Key",
    category: "Hardcoded Secrets",
    severity: "CRITICAL",
    cwe: "CWE-798",
    patterns: [
      /-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----/i,
      /(secret_key|jwt_secret|api_key|private_key)\s*=\s*['"][A-Za-z0-9+/=_\-]{8,}['"]/i,
      /const\s+(SECRET|JWT_SECRET|API_KEY|PRIVATE_KEY)\s*=\s*['"][^'"]{8,}['"]/i,
      /String\s+(SECRET|PRIVATE_KEY)\s*=\s*"[^"]{8,}"/i
    ],
    description: "Hardcoded API secret or private key found in source code.",
    remediation: "Load keys dynamically from environment variables or key management vaults.",
    references: ["https://cwe.mitre.org/data/definitions/798.html"]
  },
  {
    id: "CRYPTO-004",
    name: "Insecure Pseudo-Random Number Generation (PRNG)",
    category: "Insecure Randomness",
    severity: "HIGH",
    cwe: "CWE-330",
    patterns: [
      /\b(random\.random|random\.randint|random\.choice)\s*\(/i,
      /\bMath\.random\s*\(\)/i,
      /\brand\(\)/i,
      /new\s+java\.util\.Random\s*\(/i
    ],
    description: "Standard PRNG used for security or token generation.",
    remediation: "Use CSPRNG (`crypto.getRandomValues()`, Python `secrets`, Java `SecureRandom`).",
    references: ["https://cwe.mitre.org/data/definitions/330.html"]
  },
  {
    id: "CRYPTO-005",
    name: "Insecure Symmetric Cipher Mode (ECB Mode)",
    category: "Weak Symmetric Encryption",
    severity: "HIGH",
    cwe: "CWE-327",
    patterns: [
      /AES\.MODE_ECB/i,
      /Cipher\.getInstance\(\s*['"]AES\/ECB\//i,
      /createCipheriv\(\s*['"]aes-[0-9]+-ecb/i,
      /MODE_ECB/i
    ],
    description: "AES Electronic Codebook (ECB) mode detected.",
    remediation: "Switch to AES-GCM or ChaCha20-Poly1305 authenticated encryption modes.",
    references: ["https://cwe.mitre.org/data/definitions/327.html"]
  },
  {
    id: "CRYPTO-006",
    name: "Weak / Insecure Cipher Algorithm & Key Size",
    category: "Insecure Key Sizes & Weak Ciphers",
    severity: "HIGH",
    cwe: "CWE-326",
    patterns: [
      /\b(DES|3DES|TripleDES|RC4|Blowfish)\b/i,
      /KeyPairGenerator\.getInstance\([^)]+\).*\b(512|1024)\b/i,
      /key_size\s*=\s*(512|1024)/i
    ],
    description: "Weak cipher (DES/RC4) or small RSA key size (< 2048 bits) detected.",
    remediation: "Use AES-256 or minimum 2048-bit (recommended 3072+) RSA or ECC Ed25519 keys.",
    references: ["https://cwe.mitre.org/data/definitions/326.html"]
  },
  {
    id: "CRYPTO-009",
    name: "Weak / Insecure TLS & SSL Certificate Validation",
    category: "Weak TLS & Certificate Problems",
    severity: "HIGH",
    cwe: "CWE-295",
    patterns: [
      /ssl\._create_unverified_context/i,
      /verify\s*=\s*False/i,
      /rejectUnauthorized\s*:\s*false/i,
      /TrustAllManager|ALLOW_ALL_HOSTNAME_VERIFIER/i
    ],
    description: "TLS certificate or host verification is disabled.",
    remediation: "Enforce strict TLS validation and certificate chain checking.",
    references: ["https://cwe.mitre.org/data/definitions/295.html"]
  },
  {
    id: "CRYPTO-010",
    name: "Insecure JWT Configuration",
    category: "Insecure JWT Configurations",
    severity: "CRITICAL",
    cwe: "CWE-347",
    patterns: [
      /alg['"]?\s*:\s*['"]none['"]/i,
      /jwt\.decode\([^)]*verify\s*=\s*False/i,
      /verify_signature\s*:\s*false/i
    ],
    description: "JWT permits unsigned 'none' algorithm or bypasses signature verification.",
    remediation: "Whitelist trusted algorithms (HS256/RS256) and strictly verify signatures.",
    references: ["https://cwe.mitre.org/data/definitions/347.html"]
  }
];
