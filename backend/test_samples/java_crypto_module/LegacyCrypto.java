package com.legacy.security;

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
}
