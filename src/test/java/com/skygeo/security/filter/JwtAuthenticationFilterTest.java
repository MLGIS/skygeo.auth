package com.skygeo.security.filter;

import com.skygeo.security.service.JwtService;
import com.skygeo.security.config.properties.SecurityProperties;
import com.skygeo.security.config.properties.SecurityUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class JwtAuthenticationFilterTest {

    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private SecurityProperties securityProperties;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    private UserDetails createUserDetails(SecurityUser securityUser) {
        List<SimpleGrantedAuthority> authorities = Arrays.stream(securityUser.getRoles().split(","))
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.trim()))
                .collect(Collectors.toList());

        return User.builder()
                .username(securityUser.getUsername())
                .password(securityUser.getPassword())
                .authorities(authorities)
                .build();
    }

    @Test
    void whenValidConfiguredUser_thenAuthenticateSuccess() {
        // Get admin user from config
        SecurityUser configUser = securityProperties.getUsers().stream()
                .filter(user -> user.getUsername().equals("admin"))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("Admin user not found"));

        UserDetails userDetails = createUserDetails(configUser);
        
        String token = jwtService.generateToken(userDetails);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        String username = jwtService.extractUsername(token);
        assertEquals("admin", username);
        assertTrue(jwtService.isTokenValid(token, userDetails));
    }

    @Test
    void whenInvalidUser_thenAuthenticateFails() {
        String nonExistentUser = "nonexistent";
        assertFalse(securityProperties.getUsers().stream()
                .anyMatch(user -> user.getUsername().equals(nonExistentUser)));
    }

    @Test
    void whenManagerUser_thenHasCorrectRoles() {
        SecurityUser managerUser = securityProperties.getUsers().stream()
                .filter(user -> user.getUsername().equals("manager"))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("Manager user not found"));

        UserDetails userDetails = createUserDetails(managerUser);
        
        String token = jwtService.generateToken(userDetails);
        assertTrue(userDetails.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_MANAGER")));
        assertTrue(userDetails.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
        assertFalse(userDetails.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
    }

    @Test
    void whenInvalidToken_thenDontAuthenticate() {
        String invalidToken = "invalid.token.here";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + invalidToken);

        assertThrows(Exception.class, () -> jwtService.extractUsername(invalidToken));
    }
}