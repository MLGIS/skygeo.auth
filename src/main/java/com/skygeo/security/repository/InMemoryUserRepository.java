package com.skygeo.security.repository;

import com.skygeo.security.config.properties.SecurityProperties;
import com.skygeo.security.entity.User;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class InMemoryUserRepository implements UserRepository {
    

    @Autowired
    SecurityProperties securityProperties;

    private final Map<String, User> users = new ConcurrentHashMap<>();

    @Override
    public Optional<User> findByUsername(String username) {
        securityProperties.getUsers().forEach(user -> {

            User pUser=new User();
            pUser.setUsername(user.getUsername());
            pUser.setPassword(user.getPassword());
            pUser.setRoles(user.getRoles());

            users.put(user.getUsername(), pUser);
;        });
        return Optional.ofNullable(users.get(username));
    }

    @Override
    public User save(User user) {
        users.put(user.getUsername(), user);
        return user;
    }
}