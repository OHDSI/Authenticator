package org.ohdsi.authenticator.service;

import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
public class AuthMethodSettins {

    private String service;
    private Map config;
}
