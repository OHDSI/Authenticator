package org.ohdsi.authenticator.service.directory.ldap;

import org.ohdsi.authenticator.service.directory.DirectoryBasedAuthService;

public class LdapAuthService extends DirectoryBasedAuthService<LdapAuthServiceConfig> {

    public static final String AUTH_METHOD_NAME = "LDAP";

    public LdapAuthService(LdapAuthServiceConfig config, String method) {

        super(config, method);
    }

    @Override
    public String getMethodType() {

        return AUTH_METHOD_NAME;
    }

}
