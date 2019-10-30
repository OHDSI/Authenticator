package org.ohdsi.authenticator.service;

import io.jsonwebtoken.Claims;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;

@Component
public class TokenProviderDecorator implements TokenProvider {

    private JwtTokenProvider jwtTokenProvider;
    private GoogleIapTokenProvider googleIapTokenProvider;

    public TokenProviderDecorator(JwtTokenProvider jwtTokenProvider, GoogleIapTokenProvider googleIapTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.googleIapTokenProvider = googleIapTokenProvider;
    }

    @Override
    public void invalidateToken(AccessToken token) {
        getProviderByType(token).invalidateToken(token);
    }

    @Override
    public Claims validateTokenAndGetClaims(AccessToken token) {
        return getProviderByType(token).validateTokenAndGetClaims(token);
    }

    @Override
    public AccessToken createToken(String username, Map<String, String> userAdditionalInfo, Date expirationDate) {
        return jwtTokenProvider.createToken(username, userAdditionalInfo, expirationDate);
    }

    private TokenProvider getProviderByType(AccessToken token) {
        if (token.getType() == AccessToken.Type.IAP) {
            return googleIapTokenProvider;
        }
        return jwtTokenProvider;
    }

}
