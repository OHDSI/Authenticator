package org.ohdsi.authenticator.model;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.ohdsi.authenticator.service.authentication.Authenticator;
import org.pac4j.core.credentials.Credentials;

/**
 This class contains authentication info about user.

 You can get this info by {@link Authenticator#authenticate(String, Credentials)} or {@link Authenticator#refreshToken(String)}
 */
@Getter
@Setter
@Builder
public class UserInfo {

    private String token;
    private String username;
    private String authMethod;

    private User user;

}
