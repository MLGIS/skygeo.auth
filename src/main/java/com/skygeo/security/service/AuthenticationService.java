package com.skygeo.security.service;

import com.skygeo.security.dto.LoginRequest;
import com.skygeo.security.dto.LoginResponse;
import com.skygeo.security.dto.UserListResponse;
import com.skygeo.security.config.properties.SecurityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;
import java.util.Arrays;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Autowired
    private SecurityProperties securityProperties;

    public LoginResponse authenticate(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.getUsername(),
                request.getPassword()
            )
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String token = jwtService.generateToken(userDetails);
        
        String[] roles = userDetails.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .map(role -> role.replace("ROLE_", ""))
            .toArray(String[]::new);

        return new LoginResponse(token, userDetails.getUsername(), roles);
    }

    public List<UserListResponse> getAllUsers() {
        return securityProperties.getUsers().stream()
            .map(user -> new UserListResponse(
                user.getUsername(),
                Arrays.asList(user.getRoles().split(","))
            ))
            .collect(Collectors.toList());
    }

    public UserListResponse getCurrentUser(String token) {
        String username = jwtService.extractUsername(token);
        return securityProperties.getUsers().stream()
            .filter(user -> user.getUsername().equals(username))
            .findFirst()
            .map(user -> new UserListResponse(
                user.getUsername(),
                Arrays.asList(user.getRoles().split(","))
            ))
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}