package com.skygeo.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.skygeo.security.config.EndpointPermissionEvaluator;

import java.io.IOException;

public class EndpointAuthorizationFilter extends OncePerRequestFilter {
    
    private final EndpointPermissionEvaluator permissionEvaluator;
    
    public EndpointAuthorizationFilter(EndpointPermissionEvaluator permissionEvaluator) {
        this.permissionEvaluator = permissionEvaluator;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication != null && authentication.isAuthenticated()) {
            String requestUri = request.getRequestURI();
            String method = request.getMethod();
            
            if (!permissionEvaluator.hasPermission(authentication, requestUri, method)) {
                throw new AccessDeniedException("Access is denied");
            }
        }
        
        filterChain.doFilter(request, response);
    }
}
