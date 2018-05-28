package com.basaki.security.jwt.core;

import com.basaki.security.jwt.core.exception.InvalidCryptoException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public enum HashType {

    SHA256("SHA-256"), SHA512_384("SHA-384"), SHA512("SHA-512");

    private String algorithm;

    HashType(String algorithm) {
        this.algorithm = algorithm;
    }

    public MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            String msg =
                    "Failed to create a message digest for algorithm " + algorithm;
            log.error(msg, e);
            throw new InvalidCryptoException(msg, e);
        }
    }
}
