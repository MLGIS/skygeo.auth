package com.skygeo.security.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class WeChatSession {
    private String openId;
    private String unionId;
    private String sessionKey;
    private Integer errcode;
    private String errmsg;
}