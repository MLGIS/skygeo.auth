package com.skygeo.security.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityUser implements UserDetails {
    private String id;
    private String username;
    private String password;
    private String email;
    private boolean enabled;
    private Set<Role> roles;
    private Set<Permission> permissions;
    private ClientType clientType;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Combine role-based and direct permissions
        Set<GrantedAuthority> authorities = roles.stream()
            .flatMap(role -> {
                Set<SimpleGrantedAuthority> permissionAuthorities = role.getPermissions().stream()
                    .map(permission -> new SimpleGrantedAuthority(permission.getName()))
                    .collect(Collectors.toSet());
                permissionAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
                return permissionAuthorities.stream();
            })
            .collect(Collectors.toSet());

        // Add direct permissions
        authorities.addAll(permissions.stream()
            .map(permission -> new SimpleGrantedAuthority(permission.getName()))
            .collect(Collectors.toSet()));

        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
}