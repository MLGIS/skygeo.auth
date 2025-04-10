package com.skygeo.security.entity;

public enum ClientType {
    WECHAT_MINI("微信小程序"),
    MOBILE_WEB("移动端网页"),
    WEB("Web端"),
    ADMIN("后台管理");

    private final String description;

    ClientType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}