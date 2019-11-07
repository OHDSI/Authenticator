package org.ohdsi.authenticator.service.authentication;

import io.jsonwebtoken.Claims;

import java.util.Date;
import java.util.Map;

public interface TokenProvider {

    void invalidateToken(String token);

    Claims validateTokenAndGetClaims(String token);

    String createToken(String username, Map<String, String> userAdditionalInfo, Date expirationDate);

}
