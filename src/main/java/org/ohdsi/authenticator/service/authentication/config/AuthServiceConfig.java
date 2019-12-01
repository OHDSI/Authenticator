package org.ohdsi.authenticator.service.authentication.config;

import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.ohdsi.authenticator.service.directory.ldap.UserMappingConfig;

@Setter
@Getter
public abstract class AuthServiceConfig {

    private Map<String, String> fieldsToExtract;

    private UserMappingConfig fieldsToUser;

}
