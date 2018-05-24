package com.basaki.security.jwt.core.exception;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Created by indra.basak on 3/18/17.
 */
@NoArgsConstructor
@ToString(callSuper = true)
@Getter
@Setter
public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException(String message) {
        super(message);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
