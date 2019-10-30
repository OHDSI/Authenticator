package org.ohdsi.authenticator.service;

import org.apache.commons.lang3.StringUtils;

import java.util.Optional;
import java.util.function.Function;

public class AccessTokenResolver {

    private static final String GOOGLE_IAP_JWT_HEADER = "x-goog-iap-jwt-assertion";
    private final boolean googleIapEnabled;


    private String tokenHeader;

    public AccessTokenResolver(String tokenHeader, boolean googleIapEnabled) {
        this.tokenHeader = tokenHeader;
        this.googleIapEnabled = googleIapEnabled;
    }

    public Optional<AccessToken> getAccessToken(Function<String, String> retrieveTokenFunction) {
        if (googleIapEnabled) {
            String googleIapToken = retrieveTokenFunction.apply(GOOGLE_IAP_JWT_HEADER);
            if (StringUtils.isNotEmpty(googleIapToken)) {
                return Optional.of(AccessToken.iap(googleIapToken));
            }
            return Optional.empty();
        }

        String jwtToken = retrieveTokenFunction.apply(this.tokenHeader);
        if (StringUtils.isNotEmpty(jwtToken)) {
            return Optional.of(AccessToken.jwt(jwtToken));
        }
        return Optional.empty();
    }
}
