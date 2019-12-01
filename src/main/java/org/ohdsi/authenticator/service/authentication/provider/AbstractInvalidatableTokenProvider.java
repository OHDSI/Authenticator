package org.ohdsi.authenticator.service.authentication.provider;

import io.jsonwebtoken.Claims;
import org.apache.commons.lang3.StringUtils;
import org.ohdsi.authenticator.exception.AuthenticationException;

import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import org.ohdsi.authenticator.service.authentication.TokenProvider;

public abstract class AbstractInvalidatableTokenProvider implements TokenProvider {

    protected static final String INVALID_TOKEN_ERROR = "Expired or invalid JWT token";
    public static final String EMPTY_TOKEN_ERROR = "Empty token";
    protected Set<String> invalidatedTokens = new CopyOnWriteArraySet<>();


    @Override
    public <T> T resolveValue(String token, String key, Class<T> valueClass) {

        Claims claims = validateTokenAndGetClaims(token);
        return claims.get(key, valueClass);
    }

    @Override
    public void invalidateToken(String token) {
        invalidatedTokens.add(token);
    }

    protected void checkThatTokenWasNotInvalidated(String token) {

        if (token == null || StringUtils.isEmpty(token)){
            throw new AuthenticationException(EMPTY_TOKEN_ERROR);
        }
        if (invalidatedTokens.contains(token)) {
            throw new AuthenticationException(INVALID_TOKEN_ERROR);
        }
    }

}
