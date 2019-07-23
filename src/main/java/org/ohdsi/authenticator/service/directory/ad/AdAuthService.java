package org.ohdsi.authenticator.service.directory.ad;

import org.ohdsi.authenticator.model.AuthenticationToken;
import org.ohdsi.authenticator.service.directory.DirectoryBasedAuthService;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.SearchScope;
import org.springframework.util.StringUtils;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

public class AdAuthService extends DirectoryBasedAuthService<AdAuthServiceConfig> {

    public AdAuthService(AdAuthServiceConfig config) {

        super(config);
    }

    @Override
    public AuthenticationToken authenticate(Credentials credentials) {
        AuthenticationToken token = super.authenticate(credentials);
        if (token.isAuthenticated()) {
            //TODO add optional filter like group search used by WebAPI
        }
        return token;
    }

    @Override
    protected LdapQuery buildQuery(UsernamePasswordCredentials credentials) {

        String username = getFQDNUsername(credentials.getUsername());
        return query()
                .base(config.getBaseDn())
                .searchScope(SearchScope.SUBTREE)
                .filter(config.getSearchFilter(), username);
    }

    private String getFQDNUsername(String username) {

        StringBuilder sb = new StringBuilder(username);
        String domainSuffix = config.getDomainSuffix();
        if (StringUtils.hasText(domainSuffix)) {
            if (!StringUtils.trimLeadingWhitespace(domainSuffix).startsWith("@")) {
                sb.append("sb");
            }
            sb.append(domainSuffix);
        }
        return sb.toString();
    }
}
