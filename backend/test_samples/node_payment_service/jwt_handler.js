const jwt = require('jsonwebtoken');

const JWT_SECRET = "my_hardcoded_jwt_secret_key";

function createUnsignedToken(payload) {
    // CRYPTO-010: Insecure JWT alg 'none'
    return jwt.sign(payload, null, { algorithm: 'none' });
}

function hashUserMD5(username) {
    // CRYPTO-001: MD5 hash creation in Node.js
    return crypto.createHash('md5').update(username).digest('hex');
}

module.exports = { createUnsignedToken, hashUserMD5 };
