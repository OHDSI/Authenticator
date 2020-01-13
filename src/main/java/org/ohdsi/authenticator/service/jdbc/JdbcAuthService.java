package org.ohdsi.authenticator.service.jdbc;

import com.zaxxer.hikari.HikariDataSource;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.exception.BadCredentialsAuthenticationException;
import org.ohdsi.authenticator.model.TokenInfo;
import org.ohdsi.authenticator.model.User;
import org.ohdsi.authenticator.service.BaseAuthService;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.ClassUtils;

public class JdbcAuthService extends BaseAuthService<JdbcAuthServiceConfig> {

    public static final String AUTH_METHOD_NAME = "JDBC";

    private static final String USERNAME_PARAM = "username";
    private static final String PASSWORD_PARAM = "password";

    private HikariDataSource ds;
    private PasswordEncoder passwordEncoder;

    public JdbcAuthService(JdbcAuthServiceConfig config, String method) throws IllegalAccessException, InstantiationException, ClassNotFoundException {

        super(config, method);
        initConnectionPool();
        this.passwordEncoder = getPasswordEncoder();
    }

    @Override
    public TokenInfo authenticate(Credentials credentials) {
        UsernamePasswordCredentials creds = (UsernamePasswordCredentials) credentials;

        NamedParameterJdbcTemplate ps = new NamedParameterJdbcTemplate(ds);
        MapSqlParameterSource params = buildQueryParams(creds);

        try {
            User user = ps.queryForObject(
                    config.getQuery(),
                    params,
                    (rs, rowNum) -> mapUserInfo(creds, rs)
            );

            return TokenInfo.builder()
                    .authMethod(method)
                    .username(creds.getUsername())
                    .user(user)
                    .build();
        } catch (EmptyResultDataAccessException ex) {
            throw new BadCredentialsAuthenticationException(ex);
        }
    }

    @Override
    public String getMethodType() {

        return AUTH_METHOD_NAME;
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

    private User mapUserInfo(UsernamePasswordCredentials creds, ResultSet rs) {

        try {

            if (!isSuccessfulLogin(creds, rs.getString(PASSWORD_PARAM))) {
                throw new BadCredentialsAuthenticationException();
            }

            creds.getUsername();
            return attributesToUserConverter.convert(rsRowToMap(rs));
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
