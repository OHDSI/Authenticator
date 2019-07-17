package org.ohdsi.authenticator.service.rest;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RefreshTokenConfig extends TokenSource {
    private String url;
}
