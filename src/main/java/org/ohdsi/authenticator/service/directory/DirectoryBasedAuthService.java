package org.ohdsi.authenticator.service.directory;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import lombok.AllArgsConstructor;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.AuthenticationToken;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.BaseAuthService;
import org.ohdsi.authenticator.service.directory.ldap.LdapAuthServiceConfig;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.AuthenticatedLdapEntryContextMapper;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapEntryIdentification;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.DirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.HardcodedFilter;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.SearchScope;

public abstract class DirectoryBasedAuthService<T extends LdapAuthServiceConfig> extends BaseAuthService<T> {

    public static final String PASSWORD_ATTR = "password";


    protected LdapTemplate ldapTemplate;
    protected ContextSource contextSource;

    public DirectoryBasedAuthService(T config) {

        super(config);
        this.contextSource = initContextSource();
        this.ldapTemplate = initLdap();
    }


    @Override
    public AuthenticationToken authenticate(Credentials credentials) {

        if (!(credentials instanceof UsernamePasswordCredentials)) {
            throw new IllegalArgumentException("credentials should be UsernamePasswordCredentials");
        }
        UsernamePasswordCredentials passwordCredentials = (UsernamePasswordCredentials) credentials;
        Map<String, String> details = this.authenticate(passwordCredentials);

        return new AuthenticationBuilder()
                .setAuthenticated(!details.isEmpty())
                .setUsername(passwordCredentials.getUsername())
                .setUserDetails(details)
                .build();
    }

    @Override
    public Optional<UserInfo> findUser(String username) {

        LdapQuery query = query()
                .searchScope(SearchScope.SUBTREE)
                .filter(filterForSingleUser(username));

        return ldapTemplate.search(query, new AttributesToUserMapper(username)).stream().findFirst();
    }

    @Override
    public List<UserInfo> findAllUsers() {

        HardcodedFilter filter = new HardcodedFilter(config.getSearchFilter());
        LdapQuery query = query()
                .searchScope(SearchScope.SUBTREE)
                .filter(filter);

        return ldapTemplate.search(query, new AttributesToUserMapper(null));
    }

    protected ContextSource initContextSource() {

        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(config.getUrl());
        contextSource.setBase(config.getBaseDn());
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

    protected String prepareUsername(String username) {

        return username;
    }

    private Map<String, String> authenticate(UsernamePasswordCredentials passwordCredentials) {

        try {
            String username = passwordCredentials.getUsername();

            LdapQuery query = query()
                    .searchScope(SearchScope.SUBTREE)
                    .filter(filterForSingleUser(username));
            UserInfo userInfo = ldapTemplate.authenticate(query, passwordCredentials.getPassword(), new AttributesToUserMapper(username));
            return userInfo.getAdditionalInfo();
        } catch (Exception ex) {
            throw new AuthenticationException("Authentication error", ex);
        }
    }

    private AndFilter filterForSingleUser(String username) {

        return new AndFilter()
                .and(new HardcodedFilter(config.getSearchFilter()))
                .and(new EqualsFilter(
                        config.getFieldsToUser().getUsername(),
                        prepareUsername(username))
                );
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

    @AllArgsConstructor
    public class AttributesToUserMapper implements AttributesMapper<UserInfo>, AuthenticatedLdapEntryContextMapper<UserInfo> {

        private String username;

        @Override
        public UserInfo mapFromAttributes(Attributes attributes) throws NamingException {

            return mapAttributes(attributes);
        }

        @Override
        public UserInfo mapWithContext(DirContext dirContext, LdapEntryIdentification ldapEntryIdentification) {

            try {
                Attributes attributes = dirContext.getAttributes(ldapEntryIdentification.getRelativeName());
                return mapAttributes(attributes);
            } catch (NamingException e) {
                throw new RuntimeException(e);
            }
        }

        private UserInfo mapAttributes(Attributes attributes) throws NamingException {

            Map<String, String> valuesMap = new HashMap<>();
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
            valuesMap.remove(PASSWORD_ATTR);
            return extractUserDetails(username, valuesMap);
        }

    }
}
