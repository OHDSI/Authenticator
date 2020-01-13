package org.ohdsi.authenticator.service.authentication.user;

import java.util.List;
import java.util.Optional;
import org.ohdsi.authenticator.converter.TokenInfoToTokenConverter;
import org.ohdsi.authenticator.converter.TokenInfoToUserInfoConverter;
import org.ohdsi.authenticator.exception.MethodNotSupportedAuthenticationException;
import org.ohdsi.authenticator.model.TokenInfo;
import org.ohdsi.authenticator.model.User;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.AuthService;
import org.ohdsi.authenticator.service.authentication.AuthServiceProvider;
import org.ohdsi.authenticator.service.authentication.TokenProvider;
import org.ohdsi.authenticator.service.authentication.UserService;


public class AuthUserServiceImpl implements UserService {

    private TokenInfoToTokenConverter tokenInfoToTokenConverter;
    private TokenInfoToUserInfoConverter tokenInfoToUserInfoConverter;

    private AuthServiceProvider authServiceProvider;

    public AuthUserServiceImpl(TokenProvider tokenProvider,
                               AuthServiceProvider authServiceProvider) {

        this.tokenInfoToTokenConverter = new TokenInfoToTokenConverter(tokenProvider);
        this.tokenInfoToUserInfoConverter = new TokenInfoToUserInfoConverter();
        this.authServiceProvider = authServiceProvider;
    }

    @Override
    public UserInfo resolveUser(String token) {

        TokenInfo tokenInfo = tokenInfoToTokenConverter.toTokenInfo(token);
        return tokenInfoToUserInfoConverter.toUserInfo(tokenInfo, token);
    }

    @Override
    public Optional<User> findUser(String method, String username) {

        AuthService authService = authServiceProvider.getByMethod(method)
                .orElseThrow(MethodNotSupportedAuthenticationException::new);
        return authService.findUser(username);
    }

    @Override
    public List<User> findAllUsers(String method) {

        AuthService authService = authServiceProvider.getByMethod(method)
                .orElseThrow(MethodNotSupportedAuthenticationException::new);
        return authService.findAllUsers();

    }
}
