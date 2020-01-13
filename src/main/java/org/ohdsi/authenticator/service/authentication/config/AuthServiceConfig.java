package org.ohdsi.authenticator.service.authentication.config;

import lombok.Getter;
import lombok.Setter;
import org.ohdsi.authenticator.service.directory.ldap.UserMappingConfig;

@Setter
@Getter
public abstract class AuthServiceConfig {

    private UserMappingConfig fieldsToExtract;

}
