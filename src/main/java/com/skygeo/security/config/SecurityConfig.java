package com.skygeo.security.config;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

import com.skygeo.security.filter.EndpointAuthorizationFilter;

import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
            EndpointPermissionEvaluator endpointPermissionEvaluator) throws Exception {
        http
            .authorizeHttpRequests(authorize -> 
                authorize
                    .requestMatchers("/public/**", "/auth/**", "/oauth2/**").permitAll()
                    .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
            .addFilterAfter(new EndpointAuthorizationFilter(endpointPermissionEvaluator), 
                BearerTokenAuthenticationFilter.class);
        
        return http.build();
    }

    @Bean
    public Map<String, Set<String>> endpointPermissionsMap() {
        Map<String, Set<String>> endpointPermissions = new HashMap<>();
        endpointPermissions.put("GET:/api/admin/**", Set.of("ROLE_ADMIN"));
        endpointPermissions.put("POST:/api/admin/**", Set.of("ROLE_ADMIN"));
        endpointPermissions.put("GET:/api/user/**", Set.of("ROLE_USER", "ROLE_ADMIN"));
        return endpointPermissions;
    }

    @Bean
    public EndpointPermissionEvaluator endpointPermissionEvaluator(
            Map<String, Set<String>> endpointPermissionsMap) {
        return new EndpointPermissionEvaluator(endpointPermissionsMap);
    }

    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
        expressionHandler.setPermissionEvaluator(new RoleBasedPermissionEvaluator());
        return expressionHandler;
    }
}