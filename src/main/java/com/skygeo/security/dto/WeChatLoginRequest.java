package com.skygeo.security.dto;

import lombok.Data;

@Data
public class WeChatLoginRequest {
    private String code;
    private String encryptedData;
    private String iv;
}