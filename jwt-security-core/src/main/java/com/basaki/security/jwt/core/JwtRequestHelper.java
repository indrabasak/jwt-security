package com.basaki.security.jwt.core;

import com.basaki.security.jwt.core.algorithm.AlgorithmType;
import com.basaki.security.jwt.core.exception.InvalidTokenException;
import com.basaki.security.jwt.core.util.CryptoUtil;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.MessageDigest;
import java.util.Base64;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.JoseException;

import static com.basaki.security.jwt.core.util.EncoderDecoder.encode;

/**
 * Created by indra.basak on 3/18/17.
 */
public class JwtRequestHelper implements JwtMessageHelper<Request> {

    public static String ISSUER_DELIMITER = ":";

    private ObjectMapper mapper;

    public JwtRequestHelper() {
        this(new ObjectMapper());
    }

    public JwtRequestHelper(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public String create(Request request, String issuerIdentifier,
            String issuer, String audience, String user, String password,
            int expiration, AlgorithmType signingAlgo) {
        assert request != null : "Request can't be null!";
        assert issuer != null : "Issuer can't be null!";
        assert user != null : "Subject can't be null!";
        assert audience != null : "Audience can't be null!";
        assert password != null : "Password can't be null!";
        assert expiration > 0 : "Expiration time should be greater than zero!";
        assert signingAlgo != null : "Signing algorithm cannot be null!";

        JwtClaims claims = new JwtClaims();
        if (issuerIdentifier != null) {
            claims.setIssuer(issuerIdentifier + ISSUER_DELIMITER + issuer);
        } else {
            claims.setIssuer(issuer);
        }

        claims.setSubject(user);
        claims.setAudience(audience);
        claims.setExpirationTimeMinutesInTheFuture(expiration);
        claims.setNotBeforeMinutesInThePast(2);
        claims.setIssuedAtToNow();
        claims.setGeneratedJwtId();
        claims.setClaim("req", serializeRequest(request));

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(signingAlgo.name());
        //jws.setKey(key);

        jws.setHeader(HeaderParameterNames.TYPE, "JWT");

        String token;
        try {
            token = jws.getCompactSerialization();
        } catch (JoseException e) {
            throw new InvalidTokenException("Failed to serialise JWT token.",
                    e);
        }

        return token;
    }

    @Override
    public void parse(String token) {

    }

    @Override
    public void validate() {

    }

    private String serializeRequest(Request request) {
        RequestPayload payload = new RequestPayload();
        if (request.getBody() != null && request.getBody().length > 0) {
            byte[] content = request.getBody();
            MessageDigest hasher = CryptoUtil.getSha256Hash();
            hasher.update(content);
            byte[] hash = hasher.digest();
            String encodedHash = Base64.getUrlEncoder().encodeToString(hash);
            payload.setBody(encodedHash);
        }

        payload.setMethod(request.getMethod());
        payload.setPath(encode(request.getPath()));
        payload.setQuery(encode(request.getQuery()));

        try {
            return mapper.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            throw new InvalidTokenException(
                    "Request payload serialization failed!", e);
        }
    }

    @Data
    @NoArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private static class RequestPayload {

        @JsonProperty("mth")
        private String method;

        @JsonProperty("pth")
        private String path;

        @JsonProperty("qry")
        private String query;

        @JsonProperty("bdy")
        private String body;
    }
}
