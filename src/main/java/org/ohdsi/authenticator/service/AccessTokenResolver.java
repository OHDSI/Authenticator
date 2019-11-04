package org.ohdsi.authenticator.service;

import java.util.Optional;
import java.util.function.Function;
import org.apache.commons.lang3.StringUtils;

public class AccessTokenResolver {

    private static final String GOOGLE_IAP_JWT_HEADER = "x-goog-iap-jwt-assertion";
    private static final String GOOGLE_IAP_AUTH_METHOD = "iap";

    private String jwtTokenHeader;
    private String googleIapJwtHeader = GOOGLE_IAP_JWT_HEADER;

    public AccessTokenResolver(String jwtTokenHeader) {

        this.jwtTokenHeader = jwtTokenHeader;
    }

    public Optional<AccessToken> getAccessToken(String method, Function<String, String> retrieveTokenFunction) {

        AccessToken.Type type = getTypeByAuthMethod(method);
        if (type == AccessToken.Type.IAP) {
            String googleIapToken = retrieveTokenFunction.apply(googleIapJwtHeader);
            if (StringUtils.isNotEmpty(googleIapToken)) {
                return Optional.of(AccessToken.iap(googleIapToken));
            }
            return Optional.empty();
        }

        String jwtToken = retrieveTokenFunction.apply(this.jwtTokenHeader);
        if (StringUtils.isNotEmpty(jwtToken)) {
            return Optional.of(AccessToken.jwt(jwtToken));
        }
        return Optional.empty();
    }

    public static AccessToken.Type getTypeByAuthMethod(String method) {

        if (StringUtils.equalsIgnoreCase(GOOGLE_IAP_AUTH_METHOD, method)) {
            return AccessToken.Type.IAP;
        }
        return AccessToken.Type.JWT;
    }
}
