package org.ohdsi.authenticator.service.github;

import com.github.scribejava.apis.GitHubApi;
import java.util.Objects;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.TokenInfo;
import org.ohdsi.authenticator.model.User;
import org.ohdsi.authenticator.service.BaseAuthService;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.TokenCredentials;
import org.pac4j.oauth.client.OAuth20Client;
import org.pac4j.oauth.config.OAuth20Configuration;
import org.pac4j.oauth.credentials.OAuth20Credentials;
import org.pac4j.oauth.profile.OAuth20Profile;
import org.pac4j.oauth.profile.github.GitHubProfileDefinition;

public class GithubAuthService extends BaseAuthService<GithubAuthServiceConfig> {

    public static final String AUTH_METHOD_NAME = "GITHUB";

    private OAuth20Configuration oAuthConfig;
    private OAuth20Client oAuthClient;

    public GithubAuthService(GithubAuthServiceConfig config, String method) {

        super(config, method);
        this.initOAuthConfig();
        this.initOAuthClient();
    }

    @Override
    public TokenInfo authenticate(Credentials credentials) {

        TokenCredentials tokenCredentials = (TokenCredentials) credentials;

        if (Objects.isNull(tokenCredentials.getToken())) {

            String authUrl = getAuthorizationUrl();
            throw new RedirectRequiredException(authUrl);
        }

        OAuth20Credentials oAuthCredentials = new OAuth20Credentials(tokenCredentials.getToken());

        oAuthClient.getAuthenticator().validate(oAuthCredentials, null);

        OAuth20Profile profile = (OAuth20Profile) oAuthClient.getProfileCreator()
                .create(oAuthCredentials, null)
                .orElseThrow(() -> new AuthenticationException("Cannot retrieve profile"));

        String username = profile.getAttribute(config.getUsernameProperty()).toString();

        User user = attributesToUserConverter.convert(profile.getAttributes());

        return TokenInfo.builder()
                .authMethod(method)
                .username(username)
                .user(user)
                .build();
    }

    @Override
    public String getMethodType() {

        return AUTH_METHOD_NAME;
    }

    private void initOAuthConfig() {

        OAuth20Configuration oAuthConfig = new OAuth20Configuration();
        oAuthConfig.setApi(GitHubApi.instance());
        oAuthConfig.setProfileDefinition(new GitHubProfileDefinition());
        oAuthConfig.setScope(config.getScope());
        oAuthConfig.setKey(config.getApiKey());
        oAuthConfig.setSecret(config.getApiSecret());
        this.oAuthConfig = oAuthConfig;
    }

    private void initOAuthClient() {

        OAuth20Client client = new OAuth20Client();
        client.setConfiguration(this.oAuthConfig);
        client.setCallbackUrl(config.getCallbackUrl());
        client.init();
        this.oAuthClient = client;
    }

    private String getAuthorizationUrl() {

        return oAuthConfig.buildService(null, oAuthClient, null).getAuthorizationUrl();
    }

}
