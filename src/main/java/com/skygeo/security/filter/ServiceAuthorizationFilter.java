package com.skygeo.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.util.AntPathMatcher;
import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;


@Component
public class ServiceAuthorizationFilter extends OncePerRequestFilter {
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        String serviceId = request.getHeader("X-Service-ID");
        String requestUri = request.getRequestURI();
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication required");
            return;
        }

        // Get user authorities
        Set<String> userAuthorities = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toSet());

        if (!isServiceAuthorized(serviceId, requestUri, userAuthorities)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, 
                "Service " + serviceId + " with roles " + userAuthorities + 
                " is not authorized to access " + requestUri);
            return;
        }
        
        filterChain.doFilter(request, response);
    }

    private boolean isServiceAuthorized(String serviceId, String requestUri, Set<String> userAuthorities) {
        // Check if user has ADMIN role
        if (userAuthorities.contains("ROLE_ADMIN")) {
            return true;
        }

        // Check endpoint permissions
        switch (requestUri) {
            case "/api/admin/**":
                return userAuthorities.contains("ROLE_ADMIN");
            case "/api/manager/**":
                return userAuthorities.contains("ROLE_MANAGER") || 
                       userAuthorities.contains("ROLE_ADMIN");
            case "/api/user/**":
                return userAuthorities.contains("ROLE_USER") || 
                       userAuthorities.contains("ROLE_MANAGER") || 
                       userAuthorities.contains("ROLE_ADMIN");
            default:
                // For any other endpoints, check if user has any role
                return false;
        }
    }
}