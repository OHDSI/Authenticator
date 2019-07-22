package org.ohdsi.authenticator.service;

import org.ohdsi.authenticator.model.AuthenticationRequest;
import org.ohdsi.authenticator.model.UserInfo;

public interface Authenticator {

    UserInfo authenticate(String method, AuthenticationRequest request);
    String resolveUsername(String token);

    UserInfo refreshToken(String token);
    void invalidateToken(String token);
}
