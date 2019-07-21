package org.ohdsi.authenticator.service;

import org.ohdsi.authenticator.model.UserInfo;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private JwtTokenProvider jwtTokenProvider;

    public UserService(JwtTokenProvider jwtTokenProvider) {

        this.jwtTokenProvider = jwtTokenProvider;
    }

    public UserInfo getUser(String token) {

        var claims = jwtTokenProvider.resolveClaims(token);
        String subject = claims.getBody().getSubject();
        UserInfo userInfo = new UserInfo();
        userInfo.setUsername(subject);
        userInfo.setToken(token);
        return userInfo;
    }
}
