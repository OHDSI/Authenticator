package org.ohdsi.authenticator.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.ArrayList;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.ohdsi.authenticator.service.authentication.Authenticator;
import org.ohdsi.authenticator.service.authentication.UserService;
import org.pac4j.core.credentials.Credentials;

/**
 * This class contains information about authenticated user.
 *
 * This data can be retrieved by {@link Authenticator#authenticate(String, Credentials)} method or 
 * {@link UserService#resolveUser(String)}, {@link UserService#findUser(String, String)} and {@link UserService#findUser(String, String)}
 */

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class User {
    private String username;
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
    private List<String> roles = new ArrayList<>();

}