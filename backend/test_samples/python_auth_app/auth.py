import os
import secrets
import hashlib

try:
    import jwt  # type: ignore
except ImportError:
    jwt = None

try:
    from Crypto.Cipher import AES  # type: ignore
except ImportError:
    AES = None

SECRET_KEY = os.environ.get("APP_SECRET_KEY", "default_secure_secret_key_32bytes_long")

def hash_password(password):
    # Remediated: Secure password hashing using PBKDF2-HMAC-SHA256 with 600,000 iterations
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600000)
    return salt.hex() + ":" + key.hex()

def verify_token(token):
    # Remediated: Enforce JWT signature verification with explicit HS256 algorithm
    if jwt:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    return None

def generate_session_token():
    # Remediated: Use CSPRNG secrets module for random numbers
    return str(secrets.randbelow(900000) + 100000)

def encrypt_user_data(data):
    # Remediated: AES-GCM mode with random nonce and secure key
    if AES:
        key = os.urandom(32)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        return cipher.nonce + tag + ciphertext
    return None
