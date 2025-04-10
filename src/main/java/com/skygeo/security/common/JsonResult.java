package com.skygeo.security.common;

import lombok.Data;
import java.io.Serializable;
import java.time.LocalDateTime;

@Data
public class JsonResult<T> implements Serializable {
    
    private int code;
    private String message;
    private T data;
    private LocalDateTime timestamp;

    private JsonResult() {
        this.timestamp = LocalDateTime.now();
    }

    public static <T> JsonResult<T> success() {
        return success(null);
    }

    public static <T> JsonResult<T> success(T data) {
        JsonResult<T> result = new JsonResult<>();
        result.setCode(ResultCode.SUCCESS.getCode());
        result.setMessage(ResultCode.SUCCESS.getMessage());
        result.setData(data);
        return result;
    }

    public static <T> JsonResult<T> error(ResultCode resultCode) {
        JsonResult<T> result = new JsonResult<>();
        result.setCode(resultCode.getCode());
        result.setMessage(resultCode.getMessage());
        return result;
    }

    public static <T> JsonResult<T> error(ResultCode resultCode, String message) {
        JsonResult<T> result = new JsonResult<>();
        result.setCode(resultCode.getCode());
        result.setMessage(message);
        return result;
    }

    public static <T> JsonResult<T> error(int code, String message) {
        JsonResult<T> result = new JsonResult<>();
        result.setCode(code);
        result.setMessage(message);
        return result;
    }
}