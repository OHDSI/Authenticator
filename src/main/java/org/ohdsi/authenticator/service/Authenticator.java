package org.ohdsi.authenticator.service;

import org.ohdsi.authenticator.model.UserInfo;
import org.pac4j.core.credentials.Credentials;

public interface Authenticator {

    UserInfo authenticate(String method, Credentials credentials);
    String resolveUsername(String token);
    UserInfo refreshToken(String token);
    void invalidateToken(String token);
}
