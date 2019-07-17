package org.ohdsi.authenticator.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Date;

public class AuthenticationToken extends UsernamePasswordAuthenticationToken {

    @Getter
    @Setter
    private Date expirationDate;

    public AuthenticationToken(Object principal, Object credentials) {

        super(principal, credentials);
    }

    public AuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {

        super(principal, credentials, authorities);
    }
}
