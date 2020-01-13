package org.ohdsi.authenticator.service;

import java.util.List;
import java.util.Optional;
import org.ohdsi.authenticator.model.TokenInfo;
import org.ohdsi.authenticator.model.User;
import org.pac4j.core.credentials.Credentials;

public interface AuthService {

    TokenInfo authenticate(Credentials credentials);

    TokenInfo refreshToken(TokenInfo tokenInfo);

    Optional<User> findUser(String username);

    List<User> findAllUsers();

    String getMethod();

    String getMethodType();

}
