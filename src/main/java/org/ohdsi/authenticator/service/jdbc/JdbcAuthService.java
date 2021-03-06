package org.ohdsi.authenticator.service.jdbc;

import com.zaxxer.hikari.HikariDataSource;
import java.sql.ResultSetMetaData;
import lombok.var;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.AuthenticationToken;
import org.ohdsi.authenticator.service.BaseAuthService;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.ClassUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

public class JdbcAuthService extends BaseAuthService<JdbcAuthServiceConfig> {

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

        NamedParameterJdbcTemplate ps = new NamedParameterJdbcTemplate(ds);
        MapSqlParameterSource params = buildQueryParams(creds);
        Map<String, String> details = ps.queryForObject(config.getQuery(), params, this::mapUserInfo);
        boolean isAuthenticated = isSuccessfulLogin(creds, details.remove(PASSWORD_PARAM));
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

        MapSqlParameterSource params = new MapSqlParameterSource();
        params.addValue(USERNAME_PARAM, creds.getUsername());
        return params;
    }

    private Map<String, String> mapUserInfo(ResultSet rs, int rowNum) {

        try {
            Map<String, String>  details = extractUserDetails(rsRowToMap(rs));
            details.put(PASSWORD_PARAM, rs.getString(PASSWORD_PARAM));
            return details;
        } catch (SQLException ex) {
            throw new AuthenticationException(INFO_EXTRACTION_ERROR);
        }
    }

    private Map<String, Object> rsRowToMap(ResultSet rs) throws SQLException {

        Map<String, Object> result = new HashMap<>();
        ResultSetMetaData metadata = rs.getMetaData();
        int columnCount = metadata.getColumnCount();
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
