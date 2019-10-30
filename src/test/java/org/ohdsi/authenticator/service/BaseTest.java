package org.ohdsi.authenticator.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;

import java.util.Date;

public class BaseTest {

    @Autowired
    protected Authenticator authenticator;

    @Autowired
    protected JwtTokenProvider jwtTokenProvider;

    protected long getExpirationInSecs(AccessToken accessToken) {

        long expirationDateTimeFromToken = jwtTokenProvider.validateTokenAndGetClaims(accessToken).getExpiration().getTime();
        return (expirationDateTimeFromToken - new Date().getTime()) / 1000;
    }
}
