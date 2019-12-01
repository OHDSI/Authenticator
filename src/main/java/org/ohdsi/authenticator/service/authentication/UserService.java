package org.ohdsi.authenticator.service.authentication;

import java.util.List;
import java.util.Optional;
import org.ohdsi.authenticator.model.AuthenticationToken;
import org.ohdsi.authenticator.model.UserInfo;

public interface UserService {

    UserInfo resolveUser(String token);

    UserInfo buildUserInfo(AuthenticationToken authentication, String method);

    Optional<UserInfo> findUser(String method, String username);

    List<UserInfo> findAllUsers(String method);

}
