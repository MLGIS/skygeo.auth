package com.skygeo.security.common;

import lombok.Getter;

@Getter
public enum ResultCode {
    
    SUCCESS(200, "成功"),
    UNAUTHORIZED(401, "未授权"),
    FORBIDDEN(403, "禁止访问"),
    NOT_FOUND(404, "资源未找到"),
    BAD_REQUEST(400, "错误请求"),
    METHOD_NOT_ALLOWED(405, "不允许的请求方法"),
    UNSUPPORTED_MEDIA_TYPE(415, "不支持的媒体类型"),
    INTERNAL_ERROR(500, "服务器内部错误"),
    
    // Authentication specific codes
    INVALID_TOKEN(1001, "无效令牌"),
    TOKEN_EXPIRED(1002, "令牌过期"),
    INVALID_CREDENTIALS(1003, "用户名密码错误"),
    AUTHENTICATION_FAILED(1004, "认证失败"),
    BINDING_FAILED(1005, "绑定失败"),
    
    // Business specific codes
    VALIDATION_ERROR(2001, "参数验证失败"),
    DUPLICATE_ENTITY(2002, "数据重复"),
    DATA_NOT_FOUND(2003, "未找到数据"),;

    private final int code;
    private final String message;

    ResultCode(int code, String message) {
        this.code = code;
        this.message = message;
    }
}