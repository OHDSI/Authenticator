package org.ohdsi.authenticator.service.directory.ldap;

import java.util.HashMap;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserMappingConfig {

    public static final String DEFAULT_USERNAME_ATTR = "sAMAccountName";

    private String email;
    private String firstName;
    private String middleName;
    private String lastName;
    private String organization;
    private String department;
    private String affiliation;
    private String personalSummary;
    private String phone;
    private String mobile;
    private String address1;
    private String city;
    private String countryCode;
    private String zipCode;

    private String username = DEFAULT_USERNAME_ATTR;
    private String memberOf = "memberOf";


    private Map<String, String> roles = new HashMap<>();
}
