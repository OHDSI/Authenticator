package org.ohdsi.authenticator.service;

import java.util.List;
import java.util.Optional;
import lombok.Getter;
import org.ohdsi.authenticator.converter.AttributesToUserConverter;
import org.ohdsi.authenticator.model.TokenInfo;
import org.ohdsi.authenticator.model.User;
import org.ohdsi.authenticator.service.authentication.config.AuthServiceConfig;
import org.pac4j.core.credentials.Credentials;

public abstract class BaseAuthService<T extends AuthServiceConfig> implements AuthService {

    protected static final String INFO_EXTRACTION_ERROR = "Cannot extract user info";

    protected AttributesToUserConverter attributesToUserConverter;

    protected T config;

    @Getter
    protected String method;

    public BaseAuthService(T config, String method) {

        this.config = config;
        this.method = method;
        this.attributesToUserConverter = new AttributesToUserConverter(config);
    }

    @Override
    abstract public TokenInfo authenticate(Credentials credentials);

    @Override
    public TokenInfo refreshToken(TokenInfo tokenInfo) {
        return tokenInfo;
    }

    @Override
    public Optional<User> findUser(String username) {

        throw new UnsupportedOperationException(String.format("'%s' Authentication configuration with '%s' authentication method, does not support findUser method", this.method));
    }

    @Override
    public List<User> findAllUsers() {

        throw new UnsupportedOperationException(String.format("'%s' Authentication configuration with '%s' authentication method, does not support findAllUsers method", this.method));
    }

}
