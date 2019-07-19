package org.ohdsi.authenticator.service.ldap;

import org.ohdsi.authenticator.model.AuthenticationRequest;
import org.ohdsi.authenticator.model.AuthenticationToken;
import org.ohdsi.authenticator.service.AuthService;

public class LdapAuthService extends AuthService<LdapAuthServiceConfig> {

    public LdapAuthService(LdapAuthServiceConfig config) {

        super(config);
    }

    @Override
    public AuthenticationToken authenticate(AuthenticationRequest request) {

        return null;
    }
}
