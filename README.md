# Authenticator

### LDAP authentication

Authentication across directory requires special system account that used to search across directory.
`searchFilter` is a formatted LDAP query using to authenticate user. Query should include at least parameter for
    user who is logging in. Formatted parameters should be encoded like for `MessageFormat.format`. 
    Query example: `uid={0}`. To succesful authentication `searchFilter` should return exactly one record,
    if successful authentication service would try to bind to directory using distingueshed name of result node and
    provided password. 

`url` defines server URL including protocol and port, e.g. `ldap://localhost:389`
`baseDn` Distiguesh name of system account having permissions to search across directory
`password` Password of account represented by `baseDn` above
`baseDn` Distinguesh name of top level tree node that gives subtree to search into  
`countLimit` reduces count limit of search results, default is 0 meaning no restrictions
`ignorePartialResultException` when set to true partial result exceptions would be ignored, this useful when
    searching on forest, multi-domain or multi-node directories
 `searchFilter` LDAP query that should return desired user node, authentication fails when query returns no records
 
 Sample:
 
 ```yaml
 authenticator:
  methods:
    ldap:
      service: org.ohdsi.authenticator.service.directory.ldap.LdapAuthService
      config:
        baseDn: ou=users,dc=example,dc=com
        userDn: uid=admin,ou=system
        password: secret
        url: ldap://localhost:389
        searchFilter: uid={0}
        countLimit: 0
        ignorePartialResultException: true
        fieldsToExtract:
          firstName: displayName
          lastName: sn
``` 

### Active Directory authentication

Active Directory mostly is similar to LDAP authentication, except:
- `baseDn` allows to provide username istead of distingueshed name 
- `domainSuffix` AD domain name, when is not set `baseDn` should be FQDN, not just login.
- `ignorePartialResultException` should be set to `true` when authenticating across multi-domain forest

**Note:** When `domainSuffix`

Sample:

```yaml
 authenticator:
  methods:
    ad:
      service: org.ohdsi.authenticator.service.directory.ad.AdAuthService
      config:
        baseDn: DC=example,DC=com
        # Both formats works for AD either sAMAccountName (with or w/o domainSuffix) and distingueshedName
        userDn: john.doe
        password: secret
        domainSuffix: example.com
        url: ldap://pdc.example.com:389
        searchFilter: (&(userPrincipalName={0})(memberOf=CN=Users,DC=example,DC=com)
        ignorePartialResultException: true
        fieldsToExtract:
          firstName: givenName
          lastName: sn
```

## Running tests

```bash
mvn clean test \
    -Dcredentials.rest-arachne.username=user \
    -Dcredentials.rest-arachne.password=password \
    -Dcredentials.rest-atlas.username=user \ 
    -Dcredentials.rest-atlas.password=password \
    -Dwebdriver.chrome.driver=/chromedriver.exe \
    -Dauthenticator.methods.github.config.apiKey=abc123 \
    -Dauthenticator.methods.github.config.apiSecret=def567 \
    -Dcredentials.github.username=user \
    -Dcredentials.github.password=HEX_password
```
