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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.GenericFilterBean;

public class JWTAuthenticationFilter extends GenericFilterBean {

    private static final String DEFAULT_ROLE = "USER";
    private final Authenticator authenticator;

    public JWTAuthenticationFilter(Authenticator authenticator) {

        this.authenticator = authenticator;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        try {
            HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
            String authorize = httpRequest.getHeader(AuthorizationUtils.AUTHORIZE_HEADER);
            if (StringUtils.isNotBlank(authorize) && authorize.startsWith(AuthorizationUtils.BEARER_AUTH)) {
                String jwtToken = AuthorizationUtils.getToken(authorize);
                String username = authenticator.resolveUsername(jwtToken);
                if (Objects.nonNull(username) && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = new User(username, "", getAuthorities(username));
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, jwtToken,
                            userDetails.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
            filterChain.doFilter(servletRequest, servletResponse);
        } catch (AuthenticationException e) {
            logger.error("Authentication error:", e);
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
        }
    }

    private Collection<? extends GrantedAuthority> getAuthorities(String username) {

        return Collections.singletonList(new SimpleGrantedAuthority(DEFAULT_ROLE));
    }
}
