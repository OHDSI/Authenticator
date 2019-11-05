package org.ohdsi.authenticator.service;

import org.springframework.beans.factory.annotation.Autowired;

import java.util.Date;

public class BaseTest {

    @Autowired
    protected Authenticator authenticator;

    @Autowired
    protected TokenProvider tokenProvider;

    protected long getExpirationInSecs(String accessToken) {

        long expirationDateTimeFromToken = tokenProvider.validateTokenAndGetClaims(accessToken).getExpiration().getTime();
        return (expirationDateTimeFromToken - new Date().getTime()) / 1000;
    }
}
