package org.ohdsi.authenticator.service.authentication;

import java.util.List;
import java.util.Optional;
import org.ohdsi.authenticator.model.User;
import org.ohdsi.authenticator.model.UserInfo;

public interface UserService {

    UserInfo resolveUser(String token);

    Optional<User> findUser(String method, String username);

    List<User> findAllUsers(String method);

}
