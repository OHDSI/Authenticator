package org.ohdsi.authenticator.service.authentication.authenticator;

import io.jsonwebtoken.Claims;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.authentication.Authenticator;
import org.ohdsi.authenticator.service.authentication.TokenProvider;
import org.ohdsi.authenticator.service.authentication.TokenService;
import org.pac4j.core.credentials.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthenticatorProxyMode implements Authenticator {
    protected static final Logger logger = LoggerFactory.getLogger(AuthenticatorProxyMode.class.getName());

    private TokenService tokenService;
    private TokenProvider tokenProvider;

    public AuthenticatorProxyMode(TokenService tokenService,
                                  TokenProvider tokenProvider) {

        this.tokenService = tokenService;
        this.tokenProvider = tokenProvider;
    }

    @Override
    public UserInfo authenticate(String method, Credentials request) {

        throw new AuthenticationException("Authentication is delegated to the proxy level, for PROXY authentication modeю");
    }

    @Override
    public String resolveUsername(String token) {

        return tokenService.resolveAdditionalInfo(token, Claims.SUBJECT, String.class);
    }


    @Override
    public UserInfo refreshToken(String token) {

        return tokenService.resolveUser(token);
    }

    @Override
    public void invalidateToken(String token) {

        tokenProvider.invalidateToken(token);
    }


}
