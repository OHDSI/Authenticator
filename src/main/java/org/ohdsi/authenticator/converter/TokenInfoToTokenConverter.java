package org.ohdsi.authenticator.converter;

import io.jsonwebtoken.Claims;
import java.util.Map;
import org.ohdsi.authenticator.model.TokenInfo;
import org.ohdsi.authenticator.model.User;
import org.ohdsi.authenticator.service.authentication.TokenProvider;

public class TokenInfoToTokenConverter {

    private static final String METHOD_KEY = "method";
    private static final String TOKEN_KEY = "token";

    private TokenProvider tokenProvider;

    private UserToMapConverter userToMapConverter = new UserToMapConverter();

    public TokenInfoToTokenConverter(TokenProvider tokenProvider) {

        this.tokenProvider = tokenProvider;
    }

    public String toToken(TokenInfo authentication) {

        Map<String, Object> additionalInfo = userToMapConverter.toMap(authentication.getUser());
        additionalInfo.put(METHOD_KEY, authentication.getAuthMethod());
        additionalInfo.put(TOKEN_KEY, authentication.getRemoteToken());
        return tokenProvider.createToken(authentication.getUsername(), additionalInfo, authentication.getExpirationDate());
    }

    public TokenInfo toTokenInfo(String token) {

        Claims claims = tokenProvider.validateTokenAndGetClaims(token);
        String method = claims.get(METHOD_KEY, String.class);
        String remoteToken = claims.get(TOKEN_KEY, String.class);
        User user = userToMapConverter.toUser(claims);
        return TokenInfo.builder()
                .authMethod(method)
                .username(claims.getSubject())
                .remoteToken(remoteToken)
                .user(user)
                .build();
    }

}
