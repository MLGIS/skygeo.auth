package com.skygeo.security.config.properties;

import lombok.Data;

@Data
public class SecurityUser {
    private String username;
    private String password;
    private String roles;
}