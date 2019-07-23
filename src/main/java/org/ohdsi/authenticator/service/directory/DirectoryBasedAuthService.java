package org.ohdsi.authenticator.service.directory;

import lombok.var;
import org.ohdsi.authenticator.model.AuthenticationToken;
import org.ohdsi.authenticator.service.AuthService;
import org.ohdsi.authenticator.service.directory.ldap.LdapAuthServiceConfig;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.ldap.core.AuthenticatedLdapEntryContextMapper;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapEntryIdentification;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.AbstractContextSource;
import org.springframework.ldap.core.support.DirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.SearchScope;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

public abstract class DirectoryBasedAuthService<T extends LdapAuthServiceConfig> extends AuthService<T> {

    private static final String PASSWORD_ATTR = "password";
    protected LdapTemplate ldapTemplate;
    protected ContextSource contextSource;

    public DirectoryBasedAuthService(T config) {

        super(config);
        this.contextSource = initContextSource();
        this.ldapTemplate = initLdap();
    }

    protected ContextSource initContextSource() {

        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(config.getUrl());
        contextSource.setUserDn(config.getUserDn());
        contextSource.setPassword(config.getPassword());
        contextSource.setAuthenticationStrategy(getAuthenticationStrategy());
        contextSource.afterPropertiesSet();
        return contextSource;
    }

    protected LdapTemplate initLdap() {

        ldapTemplate = new LdapTemplate(this.contextSource);
        ldapTemplate.setIgnorePartialResultException(config.isIgnorePartialResultException());
        ldapTemplate.setDefaultCountLimit(config.getCountLimit());
        ldapTemplate.setDefaultTimeLimit(config.getTimeLimit());

        return ldapTemplate;
    }

    private DirContextAuthenticationStrategy getAuthenticationStrategy() {

        String className = config.getAuthenticationStrategy();
        try {
            Class<?> cls = Class.forName(className);
            if (!DirContextAuthenticationStrategy.class.isAssignableFrom(cls)) {
                throw new BeanInitializationException("AuthenticationStrategy should implement DirContextAuthenticationStrategy");
            }
            return (DirContextAuthenticationStrategy) cls.newInstance();
        } catch (IllegalAccessException | InstantiationException | ClassNotFoundException e) {
            throw new BeanInitializationException("Failed to initialize LdapAuthService", e);
        }
    }

    @Override
    public AuthenticationToken authenticate(Credentials credentials) {

        if (!(credentials instanceof UsernamePasswordCredentials)) {
            throw new IllegalArgumentException("credentials should be UsernamePasswordCredentials");
        }
        UsernamePasswordCredentials passwordCredentials = (UsernamePasswordCredentials) credentials;

        LdapQuery query = buildQuery(passwordCredentials);
        var isAuthenticated = false;
        Map<String, String> details = new HashMap<>();
        try {
            details = ldapTemplate.authenticate(query, passwordCredentials.getPassword(), new UserDetailsContextMapper());
            isAuthenticated = true;
        } catch(Exception e) {
            details.put("LAST_ERROR", e.getMessage());
        }

        return new AuthenticationBuilder()
                .setAuthenticated(isAuthenticated)
                .setUsername(passwordCredentials.getUsername())
                .setUserDetails(details)
                .build();
    }

    protected LdapQuery buildQuery(UsernamePasswordCredentials credentials) {

        return query()
                .base(config.getBaseDn())
                .searchScope(SearchScope.SUBTREE)
                .filter(config.getSearchFilter(), credentials.getUsername());
    }

    public class UserDetailsContextMapper implements AuthenticatedLdapEntryContextMapper<Map<String, String>> {

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
                throw new RuntimeException(e);
            }
            valuesMap.remove(PASSWORD_ATTR);
            return extractUserDetails(valuesMap);
        }
    }
}
