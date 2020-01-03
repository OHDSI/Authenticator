package org.ohdsi.authenticator.mapper;

import io.jsonwebtoken.Claims;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.authentication.AuthServiceProvider;
import org.ohdsi.authenticator.service.authentication.TokenProvider;

public class TokenClaimsToUserInfoConverter {

    private TokenProvider tokenProvider;

    public TokenClaimsToUserInfoConverter(TokenProvider tokenProvider) {

        this.tokenProvider = tokenProvider;
    }

    public UserInfo convert(String token) {
        Claims claims = tokenProvider.validateTokenAndGetClaims(token);
        Map<String, String> additionalInfo = claims.entrySet().stream()
                .filter(entry -> !StringUtils.equalsIgnoreCase(Claims.SUBJECT, entry.getKey()))
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        v -> v.getValue().toString())
                );

        //I don't really like the fact that we map token values to the user
        UserInfo.User user = UserInfo.User.builder()
                .username(claims.getSubject())
                .email(claims.get("email", String.class))
                .firstname(claims.get("firstName", String.class))
                .lastname(claims.get("lastName", String.class))
                .build();

        return UserInfo.builder()
                .username(user.getUsername())
                .token(token)
                .authMethod(claims.get(AuthServiceProvider.METHOD_KEY, String.class))
                .user(user)
                .additionalInfo(additionalInfo)
                .build();
    }

}
