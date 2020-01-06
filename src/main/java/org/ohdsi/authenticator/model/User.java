package org.ohdsi.authenticator.model;

import java.util.ArrayList;
import java.util.List;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class User {
    private String username;
    private String email;
    private String firstname;
    private String middlename;
    private String lastname;
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
    private List<String> roles = new ArrayList<>();
}