package org.ohdsi.authenticator.service;

import io.jsonwebtoken.Claims;

import java.util.Date;
import java.util.Map;

public interface TokenProvider {

    void invalidateToken(AccessToken token);

    Claims validateTokenAndGetClaims(AccessToken token);

    AccessToken createToken(String username, Map<String, String> userAdditionalInfo, Date expirationDate);
}
