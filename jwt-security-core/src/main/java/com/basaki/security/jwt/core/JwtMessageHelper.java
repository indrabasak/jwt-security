package com.basaki.security.jwt.core;

/**
 * Created by indra.basak on 3/18/17.
 */
public interface JwtMessageHelper<T extends Message> {

    String create(T message, String issuerIdentifier, String issuer,
            String subject, String audience, String password, int expiration);

    void parse(String token);

    void validate();
}
