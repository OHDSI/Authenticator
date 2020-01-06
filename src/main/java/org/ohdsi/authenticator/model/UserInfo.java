package org.ohdsi.authenticator.model;

import java.util.HashMap;
import java.util.Map;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class UserInfo {

    private String username;
    private String token;
    private String authMethod;

    private Map<String, String> additionalInfo = new HashMap<>();

}
