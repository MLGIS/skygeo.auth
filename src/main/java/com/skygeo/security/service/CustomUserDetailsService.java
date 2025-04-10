package com.skygeo.security.service;

import com.skygeo.security.entity.Permission;
import com.skygeo.security.entity.Role;
import com.skygeo.security.entity.SecurityUser;
import com.skygeo.security.entity.ClientType;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if ("admin".equals(username)) {
            Permission readPermission = new Permission("READ", "Read access");
            Permission writePermission = new Permission("WRITE", "Write access");
            
            Role adminRole = new Role(
                "ADMIN",
                "Administrator",
                Set.of(readPermission, writePermission)
            );
            
            return SecurityUser.builder()
                .id("1")
                .username("admin")
                .password(passwordEncoder.encode("admin123"))
                .email("admin@example.com")
                .enabled(true)
                .roles(Set.of(adminRole))
                .permissions(Set.of(readPermission))
                .clientType(ClientType.ADMIN)
                .build();
        } else if ("mobile_user".equals(username)) {
            Permission readPermission = new Permission("READ", "Read access");
            
            Role userRole = new Role(
                "USER",
                "Mobile User",
                Set.of(readPermission)
            );
            
            return SecurityUser.builder()
                .id("2")
                .username("mobile_user")
                .password(passwordEncoder.encode("user123"))
                .email("mobile@example.com")
                .enabled(true)
                .roles(Set.of(userRole))
                .permissions(Set.of(readPermission))
                .clientType(ClientType.MOBILE_WEB)
                .build();
        } else if ("mini_program".equals(username)) {
            Permission readPermission = new Permission("READ", "Read access");
            
            Role miniRole = new Role(
                "MINI_USER",
                "Mini Program User",
                Set.of(readPermission)
            );
            
            return SecurityUser.builder()
                .id("3")
                .username("mini_program")
                .password(passwordEncoder.encode("mini123"))
                .email("mini@example.com")
                .enabled(true)
                .roles(Set.of(miniRole))
                .permissions(Set.of(readPermission))
                .clientType(ClientType.WECHAT_MINI)
                .build();
        } else if (username.startsWith("mini_program_")) {
            String openId = username.substring("mini_program_".length());
            Permission readPermission = new Permission("READ", "Read access");
            
            Role miniRole = new Role(
                "MINI_USER",
                "Mini Program User",
                Set.of(readPermission)
            );
            
            return SecurityUser.builder()
                .id(openId)
                .username(username)
                .password("") // WeChat users don't need password
                .email("")
                .enabled(true)
                .roles(Set.of(miniRole))
                .permissions(Set.of(readPermission))
                .clientType(ClientType.WECHAT_MINI)
                .build();
        }
        
        throw new UsernameNotFoundException("User not found: " + username);
    }
}