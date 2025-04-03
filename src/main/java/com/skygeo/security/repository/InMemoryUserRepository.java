package com.skygeo.security.repository;

import com.skygeo.security.config.properties.SecurityProperties;
import com.skygeo.security.entity.Role;
import com.skygeo.security.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Repository
public class InMemoryUserRepository implements UserRepository {
    
    @Autowired
    private SecurityProperties securityProperties;

    private final Map<String, User> users = new ConcurrentHashMap<>();

    public Optional<User> findByUsername(String username) {
        securityProperties.getUsers().forEach(user -> {
            User pUser = new User();
            pUser.setUsername(user.getUsername());
            pUser.setPassword(user.getPassword());
            pUser.setRoles(Arrays.stream(user.getRoles().split(","))
                .map(roleName -> {
                    Role role = new Role();
                    role.setName(roleName);
                    return role;
                })
                .collect(Collectors.toSet()));
            users.put(user.getUsername(), pUser);
        });
        return Optional.ofNullable(users.get(username));
    }

    public Set<String> findUserPermissions(String username) {
        return findByUsername(username)
            .map(user -> user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(permission -> permission.getName())
                .collect(Collectors.toSet()))
            .orElse(Set.of());
    }

    public User save(User user) {
        users.put(user.getUsername(), user);
        return user;
    }
}