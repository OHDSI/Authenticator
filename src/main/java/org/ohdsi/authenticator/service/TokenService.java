package org.ohdsi.authenticator.service;

import org.ohdsi.authenticator.model.UserInfo;

public interface TokenService {

    UserInfo resolveUser(AccessToken token);

    <T> T resolveAdditionalInfo(AccessToken token, String key, Class<T> valueClass);
}
