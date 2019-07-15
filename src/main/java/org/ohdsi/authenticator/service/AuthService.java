package org.ohdsi.authenticator.service;

import lombok.var;
import org.ohdsi.authenticator.model.AuthenticationRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.ArrayList;
import java.util.Map;

public abstract class AuthService<T extends AuthServiceConfig> {

    protected static final String INFO_EXTRACTION_ERROR = "Cannot extract user info";

    protected T config;

    public AuthService(T config) {

        this.config = config;
    }

    abstract public Authentication authenticate(AuthenticationRequest request);

    public class AuthenticationBuilder {

        private boolean authenticated = false;
        private String username;
        private Map<String, String> details;

        public AuthenticationBuilder setAuthenticated(boolean authenticated) {

            this.authenticated = authenticated;
            return this;
        }

        public AuthenticationBuilder setUsername(String username) {

            this.username = username;
            return this;
        }

        public AuthenticationBuilder setUserDetails(Map<String, String> details) {

            this.details = details;
            return this;
        }

        public Authentication build() {

            if (authenticated) {
                var token = new UsernamePasswordAuthenticationToken(username, "", new ArrayList<>());
                token.setDetails(details);
                return token;
            } else {
                return new UsernamePasswordAuthenticationToken(username, "");
            }
        }
    }
}
