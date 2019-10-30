package org.ohdsi.authenticator.model;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;

@Getter
@Setter
@Builder
public class UserInfo {

    private String username;
    private String token;
    private String authMethod;
    private Map<String, Object> additionalInfo = new HashMap<>();

}
