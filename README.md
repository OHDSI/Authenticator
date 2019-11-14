# Authenticator

## Overview

Authenticator is a shared component which encapsulates authentication services required by OHDSI tools. Its goal is to reduce amount of effort required to implement and support authentication in multiple applications, provide single source of truth. 

Currently supported modes:
- Standard
- Proxy

Currently supported methods:
- Database (JDBC)
- REST
- Github
- LDAP
- Active Directory



## PROXY authentication mode 
The proxy mode means that your application is deployed on an environment behind a proxy. 
This proxy takes full responsibility for the authentication, and transfer to us only an access token in a request header.
This mode is currently implemented for IAP(Identity-Aware Proxy) https://cloud.google.com/iap/
 
### Configuration

- `security.authentication.mode` specifies authentication mode. `PROXY` value activates proxy mode 
- `security.googleIap.cloudProjectId` specifies project id of the Google cloud platform https://cloud.google.com/resource-manager/docs/creating-managing-projects
- `security.googleIap.backendServiceId` specifies backend service id for Google cloud platform https://cloud.google.com/load-balancing/docs/backend-service 
 
Sample:
```
security:
  authentication:
    mode: PROXY
  googleIap:
    cloudProjectId: 42
    backendServiceId: 42
```

## STANDARD authentication mode
The standard authentication mode means that your application  takes care of the authentication process by itself. 
 
### Configuration
The `STANDARD` authentication mode is the default mode, so it is not necessary to explicitly configure it. 

Common configuration parameters:

- `fieldsToExtract`:
  - keys represent names of user's properties, which will be stored in JWT body / UserInfo.additionalInfo
  - values represent SpEL expressions used to extract and calculate value of the properties based on the data provided by authentication origin 

#### Database (JDBC) authentication

- SQL query must return a single row
- SQL query must return user's password hash in a `password` field
- Password hashes are compared using any subclass of `org.springframework.security.crypto.password.PasswordEncoder` specified in `passwordEncoder` parameter

Sample:
```
authenticator:
  methods:
    db:
      service: org.ohdsi.authenticator.service.jdbc.JdbcAuthService
      config:
        jdbcUrl: jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1
        username: user
        password: secret
        query: SELECT PASSWORD, FIRST_NAME, MIDDLE_NAME, LAST_NAME FROM USERS WHERE USERNAME = :username
        passwordEncoder: org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
        fieldsToExtract:
          firstName: FIRST_NAME
          middleName: MIDDLE_NAME
          lastName: LAST_NAME
```

#### REST authentication

- `bodyFormat` specifies content type of request submitted to authentication endpoint
- `params` specify content of the request where `username` and `password` are substituted with provided credentials
- `loginSuccessCriteria` define criteria to determine whether login was successful
  - `bodyProperty` is defined in form of [JsonPath](https://github.com/json-path/JsonPath)
- `token.source` and `token.key` define how to extract authentication token from REST response
- `token.targetHeader` and `token.targetFormat` define how to attach the token to the next HTTP query for pulling user info
- `token.copyExpirationDate` defines whether to copy expiration date from the remote token to the token generated by Authenticator
- `infoUrl` defines which URL to query for user info
- `proxy.enabled` enable proxy connection. Default value is false 
- `proxy.host` defines proxy host
- `proxy.port` defines proxy port 
- `proxy.authEnabled` enable basic proxy authentication 
- `proxy.username` proxy username
- `proxy.password` proxy password
- If `refresh` is set, the service will do the appropriate call to the remote service when `Authenticator.refreshToken` is called

Sample:
```
authenticator:
  methods:
    rest-arachne:
      service: org.ohdsi.authenticator.service.rest.RestAuthService
      config:
        url: https://www.arachnenetwork.com/api/v1/auth/login
        bodyFormat: JSON
        params:
          username: username
          password: password
        loginSuccessCriteria:
          status: OK
          bodyProperty: '$[?(@.errorCode == 0)]'
        token:
          source: BODY
          key: $.result.token
          targetHeader: Arachne-Auth-Token
          targetFormat: '%s'
          copyExpirationDate: true
        infoUrl: https://www.arachnenetwork.com/api/v1/auth/me
        fieldsToExtract:
          firstName: result.firstname
          middleName: result.middlename
          lastName: result.lastname
        refresh:
          url: https://www.arachnenetwork.com/api/v1/auth/refresh
          source: BODY
          key: $.result
        proxy:
          enabled: true
          host: proxy-url.com
          port: 8080
          authEnabled: true
          username: user
          password: password
```

#### Github

- `apiKey` and `apiSecret` should be copied from [Github's OAuth Apps page](https://github.com/settings/developers)
- `usernameProperty` defines a property which value will be used as a username of authenticated user

Sample:
```
authenticator:
  methods:
    github:
      service: org.ohdsi.authenticator.service.github.GithubAuthService
      config:
        apiKey: somekey
        apiSecret: somesecret
        scope: user:email
        callbackUrl: http://localhost:8080/authentication/login
        usernameProperty: email
        fieldsToExtract:
          firstName: name.split(' ')[0]
          lastName: name.split(' ')[1]
```
#### LDAP authentication

Authentication across directory requires special system account that is used to conduct search.
`searchFilter` is a formatted LDAP query used to authenticate user. Query should include at least a parameter for
    user who is logging in. Formatted parameters should be encoded to fit [`MessageFormat.format`](https://docs.oracle.com/javase/8/docs/api/java/text/MessageFormat.html]). 
    Query example: `uid={0}`. For succesful authentication `searchFilter` must return exactly one record.
    When a single record is found, authentication service will try to bind to directory using distinguished name of result node and
    provided password. 

`url` defines server URL including protocol and port, e.g. `ldap://localhost:389`
`userDn` Distinguished name of system account having permissions to search across directory
`password` Password of the account
`baseDn` Distingueshed name of the top level tree node that gives subtree to search across  
`countLimit` reduces count limit of search results, default is 0 meaning no restrictions
`ignorePartialResultException` when set to true partial result exceptions are ignored, this is useful when
    searching on forest, multi-domain or multi-node directories
 `searchFilter` LDAP query that should return desired user node, authentication fails when the query returns no records
 
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

#### Active Directory authentication

Active Directory mostly is similar to LDAP authentication, except:
- `baseDn` allows to provide username instead of distinguished name 
- `domainSuffix` defines AD domain name. When is not set `baseDn` must have format of FQDN (not just login).
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
