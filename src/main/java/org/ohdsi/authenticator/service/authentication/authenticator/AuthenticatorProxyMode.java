package org.ohdsi.authenticator.service.authentication.authenticator;

import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.authentication.Authenticator;
import org.ohdsi.authenticator.service.authentication.TokenProvider;
import org.ohdsi.authenticator.service.authentication.UserService;
import org.pac4j.core.credentials.Credentials;



@Slf4j
public class AuthenticatorProxyMode implements Authenticator {

    private UserService userService;
    private TokenProvider tokenProvider;

    public AuthenticatorProxyMode(UserService userService,
                                  TokenProvider tokenProvider) {

        this.userService = userService;
        this.tokenProvider = tokenProvider;
    }

    @Override
    public UserInfo authenticate(String method, Credentials request) {

        throw new AuthenticationException("Authentication is delegated to the proxy level, for PROXY authentication mode.");
    }

    @Override
    public String resolveUsername(String token) {

        return tokenProvider.resolveValue(token, Claims.SUBJECT, String.class);
    }


    @Override
    public UserInfo refreshToken(String token) {

        UserInfo userInfo = userService.resolveUser(token);
        userInfo.getUser().setUsername(userInfo.getUsername());
        return userInfo;
    }

    @Override
    public void invalidateToken(String token) {

        tokenProvider.invalidateToken(token);
    }

}
