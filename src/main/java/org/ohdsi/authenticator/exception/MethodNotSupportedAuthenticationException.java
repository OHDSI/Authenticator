package org.ohdsi.authenticator.exception;

public class MethodNotSupportedAuthenticationException extends AuthenticationException {

    public static final String METHOD_NOT_SUPPORTED_ERROR = "Method not supported";

    public MethodNotSupportedAuthenticationException(Throwable throwable) {

        super(METHOD_NOT_SUPPORTED_ERROR, throwable);
    }

    public MethodNotSupportedAuthenticationException() {

        super(METHOD_NOT_SUPPORTED_ERROR);
    }
}
