package org.ohdsi.authenticator.service.github;

import lombok.Getter;
import lombok.Setter;
import org.ohdsi.authenticator.service.authentication.config.AuthServiceConfig;

@Getter
@Setter
public class GithubAuthServiceConfig extends AuthServiceConfig {

    private String apiKey;
    private String apiSecret;
    private String scope;
    private String callbackUrl;
    private String usernameProperty;
}
