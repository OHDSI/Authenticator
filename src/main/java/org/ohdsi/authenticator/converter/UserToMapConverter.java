package org.ohdsi.authenticator.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import org.ohdsi.authenticator.model.User;

public class UserToMapConverter {

    private static final ObjectMapper mapper = new ObjectMapper();

    public Map<String, Object> toMap(User user) {
        return mapper.convertValue(user, Map.class);
    }

    public User toUser(Map<String, ? extends Object> map) {
        return  mapper.convertValue(map, User.class);
    }

}
