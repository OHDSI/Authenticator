package org.ohdsi.authenticator.service;

import org.springframework.beans.factory.annotation.Autowired;

import java.util.Date;

public class BaseTest {

    @Autowired
    protected Authenticator authenticator;

    @Autowired
    protected JwtTokenProvider jwtTokenProvider;

    protected long getExpirationInSecs(String token) {

        long expirationDateTimeFromToken = jwtTokenProvider.validateAndResolveClaims(token).getBody().getExpiration().getTime();
        return (expirationDateTimeFromToken - new Date().getTime()) / 1000;
    }
}
