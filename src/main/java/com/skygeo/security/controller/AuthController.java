package com.skygeo.security.controller;

import com.skygeo.security.dto.LoginRequest;
import com.skygeo.security.dto.LoginResponse;
import com.skygeo.security.dto.UserListResponse;
import com.skygeo.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.authenticate(request));
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ABC')")
    public ResponseEntity<List<UserListResponse>> getAllUsers() {
        return ResponseEntity.ok(authService.getAllUsers());
    }

    @GetMapping("/users/current")
    public ResponseEntity<UserListResponse> getCurrentUser(@RequestHeader("Authorization") String token) {
        return ResponseEntity.ok(authService.getCurrentUser(token.substring(7)));
    }
}