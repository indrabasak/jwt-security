package com.basaki.security.jwt.core;

import com.basaki.security.jwt.core.algorithm.AlgorithmType;

/**
 * Created by indra.basak on 3/18/17.
 */
public interface JwtMessageHelper<T extends Message> {

    String create(T message, String issuerIdentifier, String issuer,
            String audience, String user, String password,
            int expiration, AlgorithmType signingAlgo);

    void parse(String token);

    void validate();
}
