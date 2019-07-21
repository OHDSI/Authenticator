package org.ohdsi.authenticator.service.jdbc;

import com.zaxxer.hikari.HikariDataSource;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.AuthenticationToken;
import org.ohdsi.authenticator.service.AuthService;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.ClassUtils;

import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

public class JdbcAuthService extends AuthService<JdbcAuthServiceConfig> {

    private static final String USERNAME_PARAM = "username";
    private static final String PASSWORD_PARAM = "password";

    private HikariDataSource ds;
    private PasswordEncoder passwordEncoder;

    public JdbcAuthService(JdbcAuthServiceConfig config) throws IllegalAccessException, InstantiationException, ClassNotFoundException {

        super(config);
        initConnectionPool();
        this.passwordEncoder = getPasswordEncoder();
    }

    @Override
    public AuthenticationToken authenticate(Credentials credentials) {

        UsernamePasswordCredentials creds = (UsernamePasswordCredentials) credentials;

        var ps = new NamedParameterJdbcTemplate(ds);
        var params = buildQueryParams(creds);
        var details = ps.queryForObject(config.getQuery(), params, this::mapUserInfo);
        var isAuthenticated = isSuccessfulLogin(creds, details.remove(PASSWORD_PARAM));
        return new AuthenticationBuilder()
                .setAuthenticated(isAuthenticated)
                .setUsername(creds.getUsername())
                .setUserDetails(details)
                .build();
    }

    private void initConnectionPool() {

        HikariDataSource ds = new HikariDataSource();
        ds.setJdbcUrl(config.getJdbcUrl());
        ds.setUsername(config.getUsername());
        ds.setPassword(config.getPassword());
        this.ds = ds;
    }

    private PasswordEncoder getPasswordEncoder() throws ClassNotFoundException, IllegalAccessException, InstantiationException {

        return (PasswordEncoder) ClassUtils.forName(config.getPasswordEncoder(), this.getClass().getClassLoader()).newInstance();
    }

    private MapSqlParameterSource buildQueryParams(UsernamePasswordCredentials creds) {

        var params = new MapSqlParameterSource();
        params.addValue(USERNAME_PARAM, creds.getUsername());
        return params;
    }

    private Map<String, String> mapUserInfo(ResultSet rs, int rowNum) {

        try {
            var details = extractUserDetails(rsRowToMap(rs));
            details.put(PASSWORD_PARAM, rs.getString(PASSWORD_PARAM));
            return details;
        } catch (SQLException ex) {
            throw new AuthenticationException(INFO_EXTRACTION_ERROR);
        }
    }

    private Map<String, Object> rsRowToMap(ResultSet rs) throws SQLException {

        var result = new HashMap<String, Object>();
        var metadata = rs.getMetaData();
        var columnCount = metadata.getColumnCount();
        for (int i = 1; i <= columnCount; i++) {
            String columnName = metadata.getColumnName(i);
            result.put(columnName, rs.getObject(columnName));
        }
        return result;
    }

    private boolean isSuccessfulLogin(UsernamePasswordCredentials credentials, String actualPassword) {

        return passwordEncoder.matches(credentials.getPassword(), actualPassword);
    }
}
