package org.ohdsi.authenticator.service;

import org.ohdsi.authenticator.model.UserInfo;

public interface TokenService {

    UserInfo resolveUser(String token);

    <T> T resolveAdditionalInfo(String token, String key, Class<T> valueClass);
}
