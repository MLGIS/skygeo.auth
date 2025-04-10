package com.skygeo.security.dto;

import java.util.List;

import com.skygeo.security.entity.WeChatUser;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginResponse {
    private String token;
    private String tokenType;
    private String username;
    private List<String> roles;
    private WeChatUser weChatInfo;
    private Boolean needBinding;
}