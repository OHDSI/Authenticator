package org.ohdsi.authenticator.service.directory.ad;

import org.ohdsi.authenticator.service.directory.DirectoryBasedAuthService;
import org.ohdsi.authenticator.service.directory.utils.LdapNameUtils;
import org.springframework.ldap.core.AuthenticationSource;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.util.StringUtils;

public class AdAuthService extends DirectoryBasedAuthService<AdAuthServiceConfig> {

    public static final String AUTH_METHOD_NAME = "AD";

    public AdAuthService(AdAuthServiceConfig config) {

        super(config);
    }

    @Override
    public String getMethodName() {

        return AUTH_METHOD_NAME;
    }

    @Override
    protected ContextSource initContextSource() {
        LdapContextSource contextSource = (LdapContextSource) super.initContextSource();
        contextSource.setAuthenticationSource(new AuthenticationSource() {
            @Override
            public String getPrincipal() {
                String username = config.getUserDn();
                return LdapNameUtils.isValidLdapName(username) ? username : getFullyQualifiedDomainNameUsername(username);
            }

            @Override
            public String getCredentials() {
                return config.getPassword();
            }
        });
        return contextSource;
    }


    @Override
    protected String prepareUsername(String username) {
        return getFullyQualifiedDomainNameUsername(username);
    }

    private String getFullyQualifiedDomainNameUsername(String username) {

        StringBuilder sb = new StringBuilder(username);
        String domainSuffix = config.getDomainSuffix();
        if (StringUtils.hasText(domainSuffix)) {
            if (!StringUtils.trimLeadingWhitespace(domainSuffix).startsWith("@")) {
                sb.append("@");
            }
            sb.append(domainSuffix);
        }
        return sb.toString();
    }
}
