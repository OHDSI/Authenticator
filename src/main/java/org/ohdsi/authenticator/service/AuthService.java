package org.ohdsi.authenticator.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.ohdsi.authenticator.model.AuthenticationRequest;
import org.ohdsi.authenticator.model.AuthenticationToken;

import java.util.ArrayList;
import java.util.Date;
import java.util.Map;

public abstract class AuthService<T extends AuthServiceConfig> {

    protected static final String INFO_EXTRACTION_ERROR = "Cannot extract user info";

    protected T config;

    public AuthService(T config) {

        this.config = config;
    }

    abstract public AuthenticationToken authenticate(AuthenticationRequest request);

    public AuthenticationToken refreshToken(Jws<Claims> claims) {

        return new AuthenticationBuilder()
            .setAuthenticated(true)
            .setUsername(claims.getBody().getSubject())
            .setUserDetails((Map) claims.getBody())
            .build();
    }

    public class AuthenticationBuilder {

        private boolean authenticated = false;
        private String username;
        private Map<String, String> details;
        private Date expirationDate;

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

        public AuthenticationBuilder setExpirationDate(Date expirationDate) {

            this.expirationDate = expirationDate;
            return this;
        }

        public AuthenticationToken build() {

            AuthenticationToken token;
            if (authenticated) {
                token = new AuthenticationToken(username, "", new ArrayList<>());
                token.setDetails(details);
            } else {
                token = new AuthenticationToken(username, "");
            }

            token.setExpirationDate(expirationDate);

            return token;
        }
    }
}
