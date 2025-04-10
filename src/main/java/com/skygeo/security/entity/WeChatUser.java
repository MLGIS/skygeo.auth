package com.skygeo.security.entity;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class WeChatUser {
    private String id;
    private String openId;
    private String unionId;
    private String sessionKey;
    private String nickname;
    private String avatarUrl;
    private Integer gender;
    private String country;
    private String province;
    private String city;
    private String language;
    private SecurityUser securityUser;
}