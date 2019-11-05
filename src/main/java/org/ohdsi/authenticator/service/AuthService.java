package org.ohdsi.authenticator.service;

import io.jsonwebtoken.Claims;
import org.ohdsi.authenticator.model.AuthenticationToken;
import org.pac4j.core.credentials.Credentials;

public interface AuthService<T extends AuthServiceConfig> {

    AuthenticationToken authenticate(Credentials credentials);

    AuthenticationToken refreshToken(Claims claims);

}
