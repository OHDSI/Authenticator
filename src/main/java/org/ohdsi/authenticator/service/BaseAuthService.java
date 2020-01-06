package org.ohdsi.authenticator.service;

import io.jsonwebtoken.Claims;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.ohdsi.authenticator.mapper.AttributesToAdditionalInfoConverter;
import org.ohdsi.authenticator.model.AuthenticationToken;
import org.ohdsi.authenticator.model.User;
import org.ohdsi.authenticator.service.authentication.config.AuthServiceConfig;
import org.pac4j.core.credentials.Credentials;

public abstract class BaseAuthService<T extends AuthServiceConfig> implements AuthService {

    protected static final String INFO_EXTRACTION_ERROR = "Cannot extract user info";

    protected T config;

    public BaseAuthService(T config) {

        this.config = config;
    }

    @Override
    abstract public AuthenticationToken authenticate(Credentials credentials);

    @Override
    public AuthenticationToken refreshToken(Claims claims) {

        return new AuthenticationBuilder()
                .setAuthenticated(true)
                .setUsername(claims.getSubject())
                .setUserDetails((Map) claims)
                .build();
    }

    @Override
    public Optional<User> findUser(String username) {

        throw new UnsupportedOperationException(String.format("'%s' Authentication configuration with '%s' authentication method, does not support findUser method", this.getMethodName()));
    }

    @Override
    public List<User> findAllUsers() {

        throw new UnsupportedOperationException(String.format("'%s' Authentication configuration with '%s' authentication method, does not support findAllUsers method", this.getMethodName()));

    }

    protected Map<String, String> extractUserDetails(String username, Map rawData) {

        AttributesToAdditionalInfoConverter converter = new AttributesToAdditionalInfoConverter(rawData, config);
        return converter.convert();
    }

    public static class AuthenticationBuilder {

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
