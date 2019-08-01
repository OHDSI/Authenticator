package org.ohdsi.authenticator.service.directory.ldap;

import org.ohdsi.authenticator.service.directory.DirectoryBasedAuthService;

public class LdapAuthService extends DirectoryBasedAuthService<LdapAuthServiceConfig> {

    public LdapAuthService(LdapAuthServiceConfig config) {

        super(config);
    }

}
