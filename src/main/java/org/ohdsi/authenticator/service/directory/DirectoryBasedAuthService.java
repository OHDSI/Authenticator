package org.ohdsi.authenticator.service.directory;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

import java.text.MessageFormat;
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

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.exception.BadCredentialsAuthenticationException;
import org.ohdsi.authenticator.model.TokenInfo;
import org.ohdsi.authenticator.model.User;
import org.ohdsi.authenticator.service.BaseAuthService;
import org.ohdsi.authenticator.service.directory.ldap.LdapAuthServiceConfig;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.DirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.filter.Filter;
import org.springframework.ldap.filter.HardcodedFilter;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.SearchScope;
import org.springframework.ldap.support.LdapEncoder;

@Slf4j
public abstract class DirectoryBasedAuthService<T extends LdapAuthServiceConfig> extends BaseAuthService<T> {

    public static final String PASSWORD_ATTR = "password";
    protected LdapTemplate ldapTemplate;
    protected ContextSource contextSource;

    public DirectoryBasedAuthService(T config, String method) {

        super(config, method);
        this.contextSource = initContextSource();
        this.ldapTemplate = initLdap();
    }


    @Override
    public TokenInfo authenticate(Credentials credentials) {

        if (!(credentials instanceof UsernamePasswordCredentials)) {
            throw new AuthenticationException("credentials should be UsernamePasswordCredentials");
        }
        UsernamePasswordCredentials passwordCredentials = (UsernamePasswordCredentials) credentials;
        User user = this.authenticate(passwordCredentials);

        return TokenInfo.builder()
                .authMethod(method)
                .username(passwordCredentials.getUsername())
                .user(user)
                .build();
    }

    @Override
    public Optional<User> findUser(String username) {

        LdapQuery query = query()
                .searchScope(SearchScope.SUBTREE)
                .filter(filterForSingleUser(username));

        return ldapTemplate
                .search(query,
                        (AttributesMapper<User>) attributes -> attributesToUserConverter.convert(username, getValuesMapFromAttributes(attributes))
                )
                .stream().findFirst();
    }

    @Override
    public List<User> findAllUsers() {

        HardcodedFilter filter = new HardcodedFilter(config.getAllUserSearchFilter());
        LdapQuery query = query()
                .searchScope(SearchScope.SUBTREE)
                .filter(filter);

        return ldapTemplate.search(query, (AttributesMapper<User>) attributes ->
                attributesToUserConverter.convert(getValuesMapFromAttributes(attributes))
        );
    }

    protected ContextSource initContextSource() {

        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(config.getUrl());
        contextSource.setBase(config.getBaseDn());
        contextSource.setUserDn(config.getUserDn());
        contextSource.setPassword(config.getPassword());
        contextSource.setAuthenticationStrategy(getAuthenticationStrategy());
        contextSource.afterPropertiesSet();

        log.debug(
            "Directory service params: url={}, baseDn={}, userDn={}, password={}",
            config.getUrl(),
            config.getBaseDn(),
            config.getUserDn(),
            config.getPassword()
        );

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

    private User authenticate(UsernamePasswordCredentials passwordCredentials) {

        try {
            String username = passwordCredentials.getUsername();

            Filter filter = filterForSingleUser(username);
            LdapQuery query = query()
                    .searchScope(SearchScope.SUBTREE)
                    .filter(filter);

            log.debug(
                "Querying Directory Based service using filter {} with password {}",
                query.toString(),
                passwordCredentials.getPassword()
            );

            return ldapTemplate.authenticate(
                    query,
                    passwordCredentials.getPassword(),
                    (dirContext, ldapEntryIdentification) -> {
                        try {
                            Attributes attributes = dirContext.getAttributes(ldapEntryIdentification.getRelativeName());
                            return attributesToUserConverter.convert(getValuesMapFromAttributes(attributes));
                        } catch (NamingException e) {
                            throw new AuthenticationException(e);
                        }
                    });
        } catch (EmptyResultDataAccessException ex) {
            throw new BadCredentialsAuthenticationException(ex);
        } catch (Exception ex) {
            if (StringUtils.contains(ex.getMessage(), "LDAP: error code 49")) {
                throw new BadCredentialsAuthenticationException(ex);
            }
            throw new AuthenticationException("Authentication error", ex);
        }
    }

    private Filter filterForSingleUser(String username) {

        return createFilterBaseOnFormattedQueryString(
                config.getSearchFilter(),
                prepareUsername(username)
        );
    }

    private HardcodedFilter createFilterBaseOnFormattedQueryString(String filterQuery, String filterParamter) {

        return new HardcodedFilter(MessageFormat.format(
                filterQuery,
                LdapEncoder.filterEncode(filterParamter))
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

    private Map<String, String> getValuesMapFromAttributes(Attributes attributes) throws NamingException {

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
        return valuesMap;
    }

}
