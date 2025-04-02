package com.skygeo.security.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ResourceController {
    
    @GetMapping("/resource")
    public String getResource(@AuthenticationPrincipal Jwt jwt) {
        return String.format("Resource accessed by: %s", jwt.getSubject());
    }
}