package org.ohdsi.authenticator.service.ldap;

import lombok.Getter;
import lombok.Setter;
import org.ohdsi.authenticator.service.AuthServiceConfig;

@Getter
@Setter
public class LdapAuthServiceConfig extends AuthServiceConfig {

    private String url;
    private String baseDn;
    private String userDn;
    private String password;
    private String searchFilter;
}
