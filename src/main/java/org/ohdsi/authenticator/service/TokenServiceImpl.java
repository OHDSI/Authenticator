package org.ohdsi.authenticator.service;

import io.jsonwebtoken.Claims;
import org.apache.commons.lang3.StringUtils;
import org.ohdsi.authenticator.model.UserInfo;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.stream.Collectors;


@Service
public class TokenServiceImpl implements TokenService {

    private TokenProvider tokenProvider;

    public TokenServiceImpl(TokenProvider tokenProviderDecorator) {
        this.tokenProvider = tokenProviderDecorator;
    }

    @Override
    public UserInfo resolveUser(String token) {

        Claims claims = tokenProvider.validateTokenAndGetClaims(token);
        Map<String, Object> additionalInfo = claims.entrySet().stream()
                .filter(entry -> !StringUtils.equalsIgnoreCase(Claims.SUBJECT, entry.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        return UserInfo.builder()
                .username(claims.getSubject())
                .authMethod(claims.get(AuthenticatorStandardMode.METHOD_KEY, String.class))
                .token(token)
                .additionalInfo(additionalInfo)
                .build();
    }

    @Override
    public <T> T resolveAdditionalInfo(String token, String key, Class<T> valueClass) {

        Claims claims = tokenProvider.validateTokenAndGetClaims(token);
        return claims.get(key, valueClass);
    }

}
