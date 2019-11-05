package org.ohdsi.authenticator.service;

public class AccessTokenResolver {

    private static final String GOOGLE_IAP_JWT_HEADER = "x-goog-iap-jwt-assertion";

    private String jwtTokenHeader;
    private AuthenticationMode authenticationMode;

    public AccessTokenResolver(String jwtTokenHeader, AuthenticationMode authenticationMode) {

        this.jwtTokenHeader = jwtTokenHeader;
        this.authenticationMode = authenticationMode;
    }

    public String getTokenHeaderName() {

        if (authenticationMode == AuthenticationMode.PROXY) {
            return GOOGLE_IAP_JWT_HEADER;
        }
        return jwtTokenHeader;
    }
}
