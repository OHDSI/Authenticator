package org.ohdsi.authenticator.service;

import org.ohdsi.authenticator.model.UserInfo;

public interface TokenService {
    UserInfo resolveUser(String token);

    String resolveAdditionalInfoAsString(String token, String key);

    <T> T resolveAdditionalInfo(String token, String key, Class<T> valueClass);
}
