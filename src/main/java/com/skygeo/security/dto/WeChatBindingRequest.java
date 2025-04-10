package com.skygeo.security.dto;

import lombok.Data;

@Data
public class WeChatBindingRequest {
    private String code;
    private String username;
    private String password;
    private UserInfo userInfo;
    
    @Data
    public static class UserInfo {
        private String nickName;
        private String avatarUrl;
        private Integer gender;
        private String country;
        private String province;
        private String city;
        private String language;
    }
}