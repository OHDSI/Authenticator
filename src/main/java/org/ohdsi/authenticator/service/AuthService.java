package org.ohdsi.authenticator.service;

import org.ohdsi.authenticator.model.AuthenticationRequest;

import java.util.Map;

public abstract class AuthService<T extends AuthServiceConfig> {

    protected static final String BAD_CREDENTIALS_ERROR = "Bad credentials";
    protected static final String INFO_EXTRACTION_ERROR = "Cannot extract user info";

    protected T config;

    public AuthService(T config) {

        this.config = config;
    }

    abstract public Map<String, String> authenticate(AuthenticationRequest request);
}
