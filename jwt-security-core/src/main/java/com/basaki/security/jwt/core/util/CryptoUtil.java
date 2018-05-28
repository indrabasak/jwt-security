package com.basaki.security.jwt.core.util;

import com.basaki.security.jwt.core.algorithm.AlgorithmType;
import com.basaki.security.jwt.core.exception.InvalidCryptoException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.keys.HmacKey;

@Slf4j
public class CryptoUtil {

    public static MessageDigest getSha256Hash() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            String msg =
                    "Failed to create a message digest for SHA-256 algorithm.";
            log.error(msg, e);
            throw new InvalidCryptoException(msg, e);
        }
    }

    /**
     * Creates a security key using {@code SHA256($user + ":" +
     * SHA256($password))}
     * as the seed data. key is used to sign a JWT for HTTP request.
     *
     * @param user     user name
     * @param password text password
     * @return a security key
     */
    public static Key createKey(AlgorithmType algo, String user,
            String password) {
        MessageDigest hasher = getSha256Hash();

        //$user + ":" + $password)
        String userPwdHash = user + ":" +
                Base64.getUrlEncoder().encodeToString(password.getBytes());

        hasher.update(userPwdHash.getBytes());
        byte[] hash = hasher.digest();
        return new HmacKey(hash);
    }
}
