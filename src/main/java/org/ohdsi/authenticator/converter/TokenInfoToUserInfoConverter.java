package org.ohdsi.authenticator.converter;

import org.ohdsi.authenticator.model.TokenInfo;
import org.ohdsi.authenticator.model.UserInfo;

public class TokenInfoToUserInfoConverter {

    public UserInfo toUserInfo(TokenInfo authentication, String token) {

        return UserInfo.builder()
                .token(token)
                .username(authentication.getUsername())
                .authMethod(authentication.getAuthMethod())
                .user(authentication.getUser())
                .build();
    }

}
