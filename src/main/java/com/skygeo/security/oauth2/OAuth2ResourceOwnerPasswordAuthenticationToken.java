package com.skygeo.security.oauth2;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

public class OAuth2ResourceOwnerPasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    private final String username;
    private final String password;
    private final Set<String> scopes;

    public OAuth2ResourceOwnerPasswordAuthenticationToken(String username, String password, 
            Authentication clientPrincipal, Set<String> scopes, Map<String, Object> additionalParameters) {
        super(new AuthorizationGrantType("password"), clientPrincipal, additionalParameters);
        Assert.hasText(username, "username cannot be empty");
        Assert.hasText(password, "password cannot be empty");
        this.username = username;
        this.password = password;
        this.scopes = Collections.unmodifiableSet(
            scopes != null ? new HashSet<>(scopes) : new HashSet<>());
    }

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }
}