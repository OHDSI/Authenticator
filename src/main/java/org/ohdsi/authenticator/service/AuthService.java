package org.ohdsi.authenticator.service;

import io.jsonwebtoken.Claims;
import java.util.List;
import java.util.Optional;
import org.ohdsi.authenticator.model.AuthenticationToken;
import org.ohdsi.authenticator.model.User;
import org.pac4j.core.credentials.Credentials;

public interface AuthService {

    AuthenticationToken authenticate(Credentials credentials);

    AuthenticationToken refreshToken(Claims claims);

    Optional<User> findUser(String username);

    List<User> findAllUsers();

    String getMethodName();

}
