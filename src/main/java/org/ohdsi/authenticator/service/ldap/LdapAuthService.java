package org.ohdsi.authenticator.service.ldap;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import lombok.var;
import org.ohdsi.authenticator.model.AuthenticationToken;
import org.ohdsi.authenticator.service.AuthService;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.ldap.core.AuthenticatedLdapEntryContextMapper;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapEntryIdentification;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.AbstractContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.core.support.SimpleDirContextAuthenticationStrategy;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.SearchScope;

public class LdapAuthService extends AuthService<LdapAuthServiceConfig> {

    private static final String PASSWORD_ATTR = "password";
    private LdapTemplate ldapTemplate;
    private ContextSource contextSource;

    public LdapAuthService(LdapAuthServiceConfig config) {

        super(config);
        initLdap();
    }

    @Override
    public AuthenticationToken authenticate(Credentials credentials) {

        UsernamePasswordCredentials passwordCredentials = (UsernamePasswordCredentials) credentials;

        LdapQuery query = query()
                .base(config.getBaseDn())
                .searchScope(SearchScope.SUBTREE)
                .filter(config.getSearchFilter(), passwordCredentials.getUsername());
        var isAuthenticated = false;
        Map<String, String> details = new HashMap<>();
        try {
            details = ldapTemplate.authenticate(query, passwordCredentials.getPassword(), new UserDetailsContextMapper());
            isAuthenticated = true;
        } catch(Exception e) {
            //TODO add reason of failure somewhere
        }

        return new AuthenticationBuilder()
                .setAuthenticated(isAuthenticated)
                .setUsername(passwordCredentials.getUsername())
                .setUserDetails(details)
                .build();
    }

    private void initLdap() {

        AbstractContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(config.getUrl());
        contextSource.setUserDn(config.getUserDn());
        contextSource.setPassword(config.getPassword());
        contextSource.setAuthenticationStrategy(new SimpleDirContextAuthenticationStrategy()); //TODO config
        contextSource.afterPropertiesSet();

        ldapTemplate = new LdapTemplate(contextSource);

        this.contextSource = contextSource;
    }

    class UserDetailsContextMapper implements AuthenticatedLdapEntryContextMapper<Map<String, String>> {

        @Override
        public Map<String, String> mapWithContext(DirContext dirContext, LdapEntryIdentification ldapEntryIdentification) {

            Map<String, String> valuesMap = new HashMap<>();
            try {
                Attributes attributes = dirContext.getAttributes(ldapEntryIdentification.getRelativeName());
                Enumeration<? extends Attribute> attrEnum = attributes.getAll();
                while (attrEnum.hasMoreElements()) {
                    Attribute attribute = attrEnum.nextElement();
                    if (attribute.size() == 1) {
                        valuesMap.put(attribute.getID(), attribute.get().toString());
                    } else {
                        NamingEnumeration valuesEnum = attribute.getAll();
                        List<String> values = new ArrayList<>();
                        while (valuesEnum.hasMore()) {
                            values.add(valuesEnum.next().toString());
                        }
                        valuesMap.put(attribute.getID(), values.stream().collect(Collectors.joining(",")));
                    }
                }
            } catch (NamingException e) {
                //TODO ???
            }
            valuesMap.remove(PASSWORD_ATTR);
            return extractUserDetails(valuesMap);
        }
    }
}
