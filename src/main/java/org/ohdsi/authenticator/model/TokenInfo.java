package org.ohdsi.authenticator.model;

import java.util.Date;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.ohdsi.authenticator.converter.TokenInfoToUserInfoConverter;


/**
 * This class contains information about access token.
 *
 * To convert token to TokenInfo and back use {@link TokenInfoToUserInfoConverter}
 */
@Getter
@Setter
@Builder
public class TokenInfo {

    private String username;
    private String authMethod;
    private Date expirationDate;

    private String remoteToken;
    private User user;
}
