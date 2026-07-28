import os
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
    return hashlib.sha256(data.encode('utf-8')).hexdigest()
