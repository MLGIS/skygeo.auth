package com.skygeo.security.repository;

import com.skygeo.security.entity.User;
import java.util.Optional;
import java.util.Set;

public interface UserRepository {
    Optional<User> findByUsername(String username);
    Set<String> findUserPermissions(String username);
    User save(User user);
}