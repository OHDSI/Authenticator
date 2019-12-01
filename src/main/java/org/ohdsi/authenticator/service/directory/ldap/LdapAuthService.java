package org.ohdsi.authenticator.service.directory.ldap;

import org.ohdsi.authenticator.service.directory.DirectoryBasedAuthService;

public class LdapAuthService extends DirectoryBasedAuthService<LdapAuthServiceConfig> {

    public static final String AUTH_METHOD_NAME = "LDAP";

    @Override
    public String getMethodName() {

        return AUTH_METHOD_NAME;
    }

    public LdapAuthService(LdapAuthServiceConfig config) {

        super(config);
    }

}
