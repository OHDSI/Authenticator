package org.ohdsi.authenticator.service;

import org.ohdsi.authenticator.model.UserInfo;
import org.pac4j.core.credentials.Credentials;

public interface Authenticator {

    UserInfo authenticate(String method, Credentials credentials);
    String resolveUsername(AccessToken token);

    UserInfo refreshToken(AccessToken token);
    void invalidateToken(AccessToken token);

}
