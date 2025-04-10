package com.skygeo.security.service;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import com.skygeo.security.dto.LoginRequest;
import com.skygeo.security.dto.LoginResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public LoginResponse login(LoginRequest request) {
        try {
            // Authenticate and get the Authentication object
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.getUsername(),
                    request.getPassword()
                )
            );

            // Get UserDetails from the authenticated object
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            // Generate token with full user details
            String token = jwtService.generateToken(userDetails);
            
            return LoginResponse.builder()
                .token(token)
                .tokenType("Bearer")
                .username(userDetails.getUsername())
                .roles(userDetails.getAuthorities().stream()
                    .map(auth -> auth.getAuthority())
                    .toList())
                .build();

        } catch (BadCredentialsException e) {
            throw new AuthenticationCredentialsNotFoundException("Invalid username or password");
        } catch (Exception e) {
            throw new AuthenticationCredentialsNotFoundException("Authentication failed: " + e.getMessage());
        }
    }
}