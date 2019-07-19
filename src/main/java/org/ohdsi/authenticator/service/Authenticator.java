package org.ohdsi.authenticator.service;

import org.ohdsi.authenticator.model.AuthenticationRequest;
import org.ohdsi.authenticator.model.UserInfo;

public interface Authenticator {

    UserInfo authenticate(String method, AuthenticationRequest request);
    UserInfo resolveUser(String token);
    String resolveUsername(String token);

    String resolveAdditionalInfoAsString(String token, String key);

    <T> T resolveAdditionalInfo(String token, String key, Class<T> valueClass);
    UserInfo refreshToken(String token);
    void invalidateToken(String token);
}
