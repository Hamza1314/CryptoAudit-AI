const crypto = require('crypto');
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
}

module.exports = { generatePaymentToken, legacyEncrypt, sendPaymentPayload };
