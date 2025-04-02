package com.skygeo.security.repository;

import com.skygeo.security.entity.User;
import java.util.Optional;

public interface UserRepository {
    Optional<User> findByUsername(String username);
    User save(User user);
}