package org.ohdsi.authenticator.service.authentication;

import org.ohdsi.authenticator.service.AuthService;

public interface AuthServiceProvider {

    String METHOD_KEY = "method";

    AuthService getByMethod(String method);

}
