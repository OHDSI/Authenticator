package org.ohdsi.authenticator.service.directory.ad;

import lombok.Getter;
import lombok.Setter;
import org.ohdsi.authenticator.service.directory.ldap.LdapAuthServiceConfig;

@Getter
@Setter
public class AdAuthServiceConfig extends LdapAuthServiceConfig {

    private String domainSuffix;
}
