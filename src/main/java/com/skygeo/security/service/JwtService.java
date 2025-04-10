package com.skygeo.security.service;

import org.springframework.security.core.userdetails.UserDetails;

import com.skygeo.security.entity.SecurityUser;
import com.skygeo.security.entity.WeChatUser;

public interface JwtService {
    String generateToken(String username);
    String generateToken(UserDetails userDetails);
    String extractUsername(String token);
    boolean isTokenValid(String token, UserDetails userDetails);
    String generateTokenWithWeChatInfo(SecurityUser securityUser, WeChatUser weChatUser);
}