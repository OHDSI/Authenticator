package org.ohdsi.authenticator.service.github;

import com.github.scribejava.apis.GitHubApi;
import lombok.var;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.AuthenticationToken;
import org.ohdsi.authenticator.service.BaseAuthService;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.TokenCredentials;
import org.pac4j.oauth.client.OAuth20Client;
import org.pac4j.oauth.config.OAuth20Configuration;
import org.pac4j.oauth.credentials.OAuth20Credentials;
import org.pac4j.oauth.profile.OAuth20Profile;
import org.pac4j.oauth.profile.github.GitHubProfileDefinition;

import java.util.Map;
import java.util.Objects;

public class GithubAuthService extends BaseAuthService<GithubAuthServiceConfig> {

    private OAuth20Configuration oAuthConfig;
    private OAuth20Client oAuthClient;

    public GithubAuthService(GithubAuthServiceConfig config) {

        super(config);
        this.initOAuthConfig();
        this.initOAuthClient();
    }

    @Override
    public AuthenticationToken authenticate(Credentials credentials) {

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

        Object username = profile.getAttribute(config.getUsernameProperty()).toString();
        Map<String, String>  details = extractUserDetails(profile);

        return new AuthenticationBuilder()
                .setAuthenticated(true)
                .setUsername(username.toString())
                .setUserDetails(details)
                .build();
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

    private Map<String, String> extractUserDetails(OAuth20Profile profile) {

        return extractUserDetails(profile.getAttributes());
    }
}
