package org.ohdsi.authenticator.service.authentication.authenticator;

import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.ohdsi.authenticator.converter.TokenInfoToTokenConverter;
import org.ohdsi.authenticator.converter.TokenInfoToUserInfoConverter;
import org.ohdsi.authenticator.exception.MethodNotSupportedAuthenticationException;
import org.ohdsi.authenticator.model.TokenInfo;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.AuthService;
import org.ohdsi.authenticator.service.authentication.Authenticator;
import org.ohdsi.authenticator.service.authentication.TokenProvider;
import org.pac4j.core.credentials.Credentials;

@Slf4j
public class AuthenticatorStandardMode implements Authenticator {

    private TokenProvider tokenProvider;
    private AuthServiceProviderImpl authServiceProvider;
    private TokenInfoToTokenConverter tokenInfoToTokenConverter;
    private TokenInfoToUserInfoConverter tokenInfoToUserInfoConverter;


    public AuthenticatorStandardMode(TokenProvider tokenProvider, AuthServiceProviderImpl authServiceProvider) {

        this.tokenProvider = tokenProvider;
        this.authServiceProvider = authServiceProvider;
        this.tokenInfoToTokenConverter = new TokenInfoToTokenConverter(tokenProvider);
        this.tokenInfoToUserInfoConverter = new TokenInfoToUserInfoConverter();
    }

    @Override
    public UserInfo authenticate(String method, Credentials request) {

        AuthService authService = authServiceProvider.getByMethod(method)
                .orElseThrow(MethodNotSupportedAuthenticationException::new);

        TokenInfo authentication = authService.authenticate(request);

        String token = tokenInfoToTokenConverter.toToken(authentication);
        return tokenInfoToUserInfoConverter.toUserInfo(authentication, token);
    }

    @Override
    public String resolveUsername(String token) {

        return tokenProvider.resolveValue(token, Claims.SUBJECT, String.class);
    }

    @Override
    public UserInfo refreshToken(String token) {

        TokenInfo tokenInfo = tokenInfoToTokenConverter.toTokenInfo(token);
        AuthService authService = authServiceProvider.getByMethod(tokenInfo.getAuthMethod())
                .orElseThrow(MethodNotSupportedAuthenticationException::new);

        TokenInfo newAuthentication = authService.refreshToken(tokenInfo);
        String newToken = tokenInfoToTokenConverter.toToken(newAuthentication);
        return tokenInfoToUserInfoConverter.toUserInfo(newAuthentication, newToken);

    }

    @Override
    public void invalidateToken(String token) {

        tokenProvider.invalidateToken(token);
    }
}
