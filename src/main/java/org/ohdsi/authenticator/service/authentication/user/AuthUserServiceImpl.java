package org.ohdsi.authenticator.service.authentication.user;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.ohdsi.authenticator.mapper.TokenClaimsToUserInfoConverter;
import org.ohdsi.authenticator.model.AuthenticationToken;
import org.ohdsi.authenticator.model.User;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.AuthService;
import org.ohdsi.authenticator.service.authentication.AuthServiceProvider;
import org.ohdsi.authenticator.service.authentication.TokenProvider;
import org.ohdsi.authenticator.service.authentication.UserService;
import org.ohdsi.authenticator.service.authentication.authenticator.AuthServiceProviderImpl;


public class AuthUserServiceImpl implements UserService {

    private TokenProvider tokenProvider;

    private AuthServiceProvider authServiceProvider;

    private TokenClaimsToUserInfoConverter tokenClaimsToUserInfoConverter;

    public AuthUserServiceImpl(TokenProvider tokenProvider,
                               AuthServiceProvider authServiceProvider,
                               TokenClaimsToUserInfoConverter tokenClaimsToUserInfoConverter) {
        this.tokenProvider = tokenProvider;
        this.authServiceProvider = authServiceProvider;
        this.tokenClaimsToUserInfoConverter = tokenClaimsToUserInfoConverter;
    }

    @Override
    public UserInfo resolveUser(String token) {
        return tokenClaimsToUserInfoConverter.convert(token);
    }

    @Override
    public UserInfo buildUserInfo(AuthenticationToken authentication, String method) {

        String username = authentication.getPrincipal().toString();

        Map<String, String> userAdditionalInfo = (Map<String, String>) authentication.getDetails();
        userAdditionalInfo.put(AuthServiceProviderImpl.METHOD_KEY, method);

        String token = tokenProvider.createToken(username, userAdditionalInfo, authentication.getExpirationDate());

        UserInfo userInfo = resolveUser(token);
        userInfo.setAdditionalInfo(userAdditionalInfo);

        return userInfo;
    }

    @Override
    public Optional<User> findUser(String method, String username) {

        AuthService authService = authServiceProvider.getByMethod(method);
        return authService.findUser(username);
    }

    @Override
    public List<User> findAllUsers(String method) {

        AuthService authService = authServiceProvider.getByMethod(method);
        return authService.findAllUsers();

    }
}
