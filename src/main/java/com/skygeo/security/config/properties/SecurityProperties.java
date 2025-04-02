package com.skygeo.security.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Data
@Component
@ConfigurationProperties(prefix = "spring.security")
public class SecurityProperties {
    private List<SecurityUser> users = new ArrayList<>();
}