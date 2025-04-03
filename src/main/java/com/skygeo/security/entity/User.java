package com.skygeo.security.entity;

import lombok.Data;
import java.util.Set;

@Data
public class User {
    private String username;
    private String password;
    private Set<Role> roles;
    private Set<Permission> permissions;
}