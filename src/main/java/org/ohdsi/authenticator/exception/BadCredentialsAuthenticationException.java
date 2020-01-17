package org.ohdsi.authenticator.exception;

public class BadCredentialsAuthenticationException extends AuthenticationException {

    public static final String BAD_CREDENTIALS_ERROR = "Bad credentials";

    public BadCredentialsAuthenticationException(Throwable throwable) {

        super(BAD_CREDENTIALS_ERROR, throwable);
    }

    public BadCredentialsAuthenticationException() {

        super(BAD_CREDENTIALS_ERROR);
    }
}
