package org.ohdsi.authenticator.filter;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.service.authentication.Authenticator;
import org.ohdsi.authenticator.util.AuthorizationUtils;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.GenericFilterBean;

public class JWTAuthenticationFilter extends GenericFilterBean {

    public static final String DEFAULT_ROLE = "USER";
    protected final Authenticator authenticator;

    public JWTAuthenticationFilter(Authenticator authenticator) {

        this.authenticator = authenticator;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        try {
            String jwtToken = getToken(httpRequest);
            if (StringUtils.isNotBlank(jwtToken)) {
                String username = authenticator.resolveUsername(jwtToken);
                if (Objects.nonNull(username) && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = getUserDetails(username);
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, jwtToken,
                            userDetails.getAuthorities());
                    onSuccessAuthentication(httpRequest, userDetails, authentication);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
            filterChain.doFilter(servletRequest, servletResponse);
        } catch (AuthenticationException e) {
            String method = httpRequest.getMethod();
            if (!HttpMethod.OPTIONS.matches(method)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Authentication failed", e);
                } else {
                    logger.error(String.format("Authentication failed: %s, requested: %s %s", e.getMessage(),
                            method, httpRequest.getRequestURI()));
                }
            }
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    protected String getToken(HttpServletRequest httpRequest) {

        String authorize = httpRequest.getHeader(AuthorizationUtils.AUTHORIZE_HEADER);
        return AuthorizationUtils.getToken(authorize);
    }

    protected void onSuccessAuthentication(HttpServletRequest request, UserDetails userDetails, AbstractAuthenticationToken authentication) {
    }

    protected UserDetails getUserDetails(String username) {

        return new User(username, "", getAuthorities(username));
    }

    protected Collection<? extends GrantedAuthority> getAuthorities(String username) {

        return Collections.singletonList(new SimpleGrantedAuthority(DEFAULT_ROLE));
    }
}
