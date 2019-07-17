package org.ohdsi.authenticator.config;

import lombok.Getter;
import lombok.Setter;
import org.ohdsi.authenticator.service.AuthMethodSettings;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "authenticator")
@Getter
@Setter
// NOTE: ConfigurationProperties seems to be the only way to make the Authenticator working in both Spring Boot 1 & 2 based apps
// due to changes in binding API
// https://github.com/spring-io/initializr/commit/fe7650f2c8b98161473d4406a8bbc5e7007ea648#diff-2aede7dc447980e1149b5948298cb231R211
public class AuthSchema {

    private Map<String, AuthMethodSettings> methods;
}
