package org.ohdsi.authenticator.exception;

public class AuthenticationException extends RuntimeException {

    public AuthenticationException(String message) {

        super(message);
    }

    public AuthenticationException(Throwable throwable) {
        super(throwable);
    }

    public AuthenticationException(String s, Throwable throwable) {
        super(s, throwable);
    }
}
