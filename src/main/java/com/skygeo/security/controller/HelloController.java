package com.skygeo.security.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@Tag(name = "Hello", description = "Hello API endpoints")
public class HelloController {
    
    @Operation(summary = "Get hello message")
    @ApiResponse(responseCode = "200", description = "Successful response")
    @GetMapping("/hello")
    public ResponseEntity<String> getHello() {
        return ResponseEntity.ok("Hello, World!");
    }
    
    @Operation(summary = "Create hello message")
    @ApiResponse(responseCode = "200", description = "Message created successfully")
    @PostMapping("/hello")
    public ResponseEntity<String> createHello(
            @Parameter(description = "Message content") 
            @RequestBody(required = false) String message) {
        return ResponseEntity.ok("Created: Hello, " + (message != null ? message : "World") + "!");
    }
    
    @Operation(summary = "Update hello message by ID")
    @ApiResponse(responseCode = "200", description = "Message updated successfully")
    @PutMapping("/hello/{id}")
    public ResponseEntity<String> updateHello(
            @Parameter(description = "Message ID") @PathVariable Long id,
            @Parameter(description = "New message content") @RequestBody String message) {
        return ResponseEntity.ok("Updated hello #" + id + ": " + message);
    }
    
    // ... other endpoints with similar annotations ...
}
