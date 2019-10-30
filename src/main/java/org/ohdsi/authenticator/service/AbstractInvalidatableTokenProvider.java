package org.ohdsi.authenticator.service;

import io.jsonwebtoken.Claims;
import org.apache.commons.lang3.StringUtils;
import org.ohdsi.authenticator.exception.AuthenticationException;

import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

public abstract class AbstractInvalidatableTokenProvider implements TokenProvider {

    protected static final String INVALID_TOKEN_ERROR = "Expired or invalid JWT token";
    public static final String EMPTY_TOKEN_ERROR = "Empty token";
    protected Set<String> invalidatedTokens = new CopyOnWriteArraySet<>();

    @Override
    public void invalidateToken(AccessToken token) {
        invalidatedTokens.add(token.getValue());
    }

    @Override
    public Claims validateTokenAndGetClaims(AccessToken token) {

        if (token == null || StringUtils.isEmpty(token.getValue())){
            throw new AuthenticationException(EMPTY_TOKEN_ERROR);
        }
        if (invalidatedTokens.contains(token.getValue())) {
            throw new AuthenticationException(INVALID_TOKEN_ERROR);
        }
        return validateAndResolveClaimsInternal(token);
    }

    protected abstract Claims validateAndResolveClaimsInternal(AccessToken token);

}
