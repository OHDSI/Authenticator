package org.ohdsi.authenticator.model;

import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;

@Getter
@Setter
public class UserInfo {

    private String username;
    private String token;
    private String authMethod;
    private Map<String, String> additionalInfo = new HashMap<>();
}
