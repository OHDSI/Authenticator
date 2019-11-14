package org.ohdsi.authenticator.service.rest.config;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ProxyConfig {
    private boolean enabled;
    private String host;
    private Integer port;
    private boolean authEnabled;
    private String username;
    private String password;
}
