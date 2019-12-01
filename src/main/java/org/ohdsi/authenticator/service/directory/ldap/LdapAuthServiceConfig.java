package org.ohdsi.authenticator.service.directory.ldap;

import lombok.Getter;
import lombok.Setter;
import org.ohdsi.authenticator.service.authentication.config.AuthServiceConfig;

@Getter
@Setter
public class LdapAuthServiceConfig extends AuthServiceConfig {

    private String url;
    private String baseDn;
    private String userDn;
    private String password;
    private String searchFilter;
    private boolean ignorePartialResultException = false;
    private int countLimit = 0;
    private int timeLimit = 0;
    private String authenticationStrategy = "org.springframework.ldap.core.support.SimpleDirContextAuthenticationStrategy";
}
