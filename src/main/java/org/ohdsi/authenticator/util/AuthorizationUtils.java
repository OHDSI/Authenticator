package org.ohdsi.authenticator.util;

import java.util.Objects;

public class AuthorizationUtils {

    public static final String BEARER_AUTH = "Bearer";
    public static final String AUTHORIZE_HEADER = "Authorization";

    public static String getToken(String header) {

        if (Objects.nonNull(header) && header.startsWith(BEARER_AUTH)) {
            return header.substring(AuthorizationUtils.BEARER_AUTH.length() + 1);
        } else {
            return null;
        }
    }
}
