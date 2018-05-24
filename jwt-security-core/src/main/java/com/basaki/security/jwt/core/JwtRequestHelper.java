package com.basaki.security.jwt.core;

import com.basaki.security.jwt.core.exception.InvalidTokenException;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.JoseException;
import org.springframework.util.Assert;

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
            String issuer, String subject, String audience, String password,
            int expiration) {
        Assert.notNull(request, "Request can't be null!");
        Assert.notNull(issuer, "Issuer can't be null!");
        Assert.notNull(subject, "Subject can't be null!");
        Assert.notNull(audience, "Audience can't be null!");
        Assert.notNull(password, "Password can't be null!");
        Assert.state((expiration > 0),
                "Expiration time should be greater than zer0!");

        JwtClaims claims = new JwtClaims();
        if (issuerIdentifier != null) {
            claims.setIssuer(issuerIdentifier + ISSUER_DELIMITER + issuer);
        } else {
            claims.setIssuer(issuer);
        }

        claims.setSubject(subject);
        claims.setAudience(audience);
        claims.setExpirationTimeMinutesInTheFuture(expiration);
        claims.setNotBeforeMinutesInThePast(2);
        claims.setIssuedAtToNow();
        claims.setGeneratedJwtId();
        claims.setClaim("req", serializeRequest(request));

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        //jws.setAlgorithmHeaderValue(algoType.getIdentifier());
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
            //            byte[] hash = getShaHash(AlgorithmType.SHA256, content);
            //            String encodedHash = Base64.getEncoder().encodeToString(hash);
            //            payload.setHash(encodedHash);
            //            payload.setAlgorithm(AlgorithmType.SHA256.name());
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

        @JsonProperty("alg")
        private String algorithm;

        @JsonProperty("bdy")
        private String body;
    }
}
