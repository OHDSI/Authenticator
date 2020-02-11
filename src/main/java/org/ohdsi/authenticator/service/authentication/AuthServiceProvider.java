package org.ohdsi.authenticator.service.authentication;

import java.util.Optional;
import org.ohdsi.authenticator.service.AuthService;

public interface AuthServiceProvider {

    Optional<AuthService> getByMethod(String method);

}
