package org.ohdsi.authenticator.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.ohdsi.authenticator.exception.AuthenticationException;

import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public abstract class AbstractTokenProvider {

    protected static final String INVALID_TOKEN_ERROR = "Expired or invalid JWT token";
    //todo yar think about threadsafe collection
    protected Set<String> invalidatedTokens = new HashSet<>();

    public void invalidateToken(String token) {
        invalidatedTokens.add(token);
    }

    public boolean isInvalidToken(String token) {
        return invalidatedTokens.contains(token);
    }

    //todo yar think about method name
    public Jws<Claims> validateAndResolveClaims(String token) {

        if (isInvalidToken(token)) {
            throw new AuthenticationException(INVALID_TOKEN_ERROR);
        }
        return validateAndResolveClaimsInner(token);
    }

    public abstract String createToken(String username, Map<String, String> userAdditionalInfo, Date expirationDate);

    protected abstract Jws<Claims> validateAndResolveClaimsInner(String token);

}
