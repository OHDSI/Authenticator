package org.ohdsi.authenticator.service.jdbc;

import lombok.Getter;
import lombok.Setter;
import org.ohdsi.authenticator.service.AuthServiceConfig;

@Getter
@Setter
public class JdbcAuthServiceConfig extends AuthServiceConfig {

    private String jdbcUrl;
    private String username;
    private String password;
    private String query;
    private String passwordEncoder;
}
