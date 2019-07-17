package org.ohdsi.authenticator.model;

import lombok.Getter;

@Getter
public class AuthenticationRequest {

    private String username;
    private String password;

    public AuthenticationRequest(String username, String password) {

        this.username = username;
        this.password = password;
    }
}
