package org.ohdsi.authenticator.service.authentication.authenticator;

import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.AuthenticationToken;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.AuthService;
import org.ohdsi.authenticator.service.authentication.Authenticator;
import org.ohdsi.authenticator.service.authentication.TokenProvider;
import org.ohdsi.authenticator.service.authentication.UserService;
import org.pac4j.core.credentials.Credentials;

@Slf4j
public class AuthenticatorStandardMode implements Authenticator {

    private static final String BAD_CREDENTIALS_ERROR = "Bad credentials";
    private static final String METHOD_NOT_SUPPORTED_ERROR = "Method not supported";

    private UserService userService;
    private TokenProvider tokenProvider;
    private AuthServiceProviderImpl authServiceProvider;


    public AuthenticatorStandardMode(UserService userService,
                                     TokenProvider tokenProvider, AuthServiceProviderImpl authServiceProvider) {

        this.userService = userService;
        this.tokenProvider = tokenProvider;
        this.authServiceProvider = authServiceProvider;
    }

    @Override
    public UserInfo authenticate(String method, Credentials request) {

        AuthService authService = authServiceProvider.getByMethod(method);

        if (authService == null) {
            throw new AuthenticationException(METHOD_NOT_SUPPORTED_ERROR);
        }

        AuthenticationToken authentication = authService.authenticate(request);

        if (!authentication.isAuthenticated()) {
            throw new AuthenticationException(BAD_CREDENTIALS_ERROR);
        }

        return userService.buildUserInfo(authentication, method);
    }

    @Override
    public String resolveUsername(String token) {

        return tokenProvider.resolveValue(token, Claims.SUBJECT, String.class);
    }

    @Override
    public UserInfo refreshToken(String token) {

        Claims claims = tokenProvider.validateTokenAndGetClaims(token);
        String usedMethod = claims.get(AuthServiceProviderImpl.METHOD_KEY, String.class);
        AuthService authService = authServiceProvider.getByMethod(usedMethod);
        AuthenticationToken authentication = authService.refreshToken(claims);
        return userService.buildUserInfo(authentication, usedMethod);
    }

    @Override
    public void invalidateToken(String token) {

        tokenProvider.invalidateToken(token);
    }
}
