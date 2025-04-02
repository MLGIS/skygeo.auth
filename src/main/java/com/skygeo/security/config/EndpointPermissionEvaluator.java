package com.skygeo.security.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
@Component
public class EndpointPermissionEvaluator {
    
    private final Map<String, Set<String>> endpointPermissions;
    
    public EndpointPermissionEvaluator(Map<String, Set<String>> endpointPermissions) {
        this.endpointPermissions = endpointPermissions;
    }
    
    public boolean hasPermission(Authentication authentication, String requestUri, String method) {
        if (!(authentication instanceof JwtAuthenticationToken)) {
            return false;
        }
        
        JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) authentication;
        Set<String> authorities = jwtAuth.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toSet());
            
        String endpointKey = method.toUpperCase() + ":" + requestUri;
        Set<String> requiredAuthorities = endpointPermissions.get(endpointKey);
        
        if (requiredAuthorities == null) {
            return false;
        }
        
        return authorities.stream()
            .anyMatch(requiredAuthorities::contains);
    }
}
