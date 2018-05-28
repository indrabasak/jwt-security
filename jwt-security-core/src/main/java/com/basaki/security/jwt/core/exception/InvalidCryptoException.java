package com.basaki.security.jwt.core.exception;

public class InvalidCryptoException extends RuntimeException {

    public InvalidCryptoException(Throwable cause) {
        super(cause);
    }

    public InvalidCryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
