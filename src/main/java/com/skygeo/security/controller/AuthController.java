package com.skygeo.security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import com.skygeo.security.dto.LoginRequest;
import com.skygeo.security.dto.LoginResponse;
import com.skygeo.security.dto.WeChatLoginRequest;
import com.skygeo.security.dto.WeChatBindingRequest;
import com.skygeo.security.service.AuthService;
import com.skygeo.security.service.WeChatAuthService;
import com.skygeo.security.common.JsonResult;
import com.skygeo.security.common.ResultCode;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final WeChatAuthService weChatAuthService;

    @PostMapping("/login")
    public JsonResult<LoginResponse> login(@RequestBody LoginRequest request) {
        try {
            LoginResponse response = authService.login(request);
            return JsonResult.success(response);
        } catch (AuthenticationCredentialsNotFoundException e) {
            return JsonResult.error(ResultCode.INVALID_CREDENTIALS);
        } catch (Exception e) {
            return JsonResult.error(ResultCode.INTERNAL_ERROR);
        }
    }

    @PostMapping("/wechat/login")
    public JsonResult<LoginResponse> wechatLogin(@RequestBody WeChatLoginRequest request) {
        try {
            LoginResponse response = weChatAuthService.authenticateWeChatUser(request);
            return JsonResult.success(response);
        } catch (Exception e) {
            return JsonResult.error(ResultCode.AUTHENTICATION_FAILED, e.getMessage());
        }
    }

    @PostMapping("/wechat/bind")
    public JsonResult<LoginResponse> bindWeChatUser(@RequestBody WeChatBindingRequest request) {
        try {
            LoginResponse response = weChatAuthService.bindWeChatUser(request);
            return JsonResult.success(response);
        } catch (Exception e) {
            return JsonResult.error(ResultCode.BINDING_FAILED, "Failed to bind WeChat user: " + e.getMessage());
        }
    }
}