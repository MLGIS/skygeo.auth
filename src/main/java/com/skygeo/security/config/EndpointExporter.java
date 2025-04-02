package com.skygeo.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
public class EndpointExporter {

    @Autowired
    private RequestMappingHandlerMapping handlerMapping;

    @Bean
    public ApplicationRunner exportEndpoints() {
        return args -> {
            // 获取所有端点映射
            Map<String, String> endpoints = handlerMapping.getHandlerMethods().entrySet().stream()
                    .collect(Collectors.toMap(
                            entry -> entry.getKey().toString(),
                            entry -> entry.getValue().getMethod().toGenericString()
                    ));

            // 将端点写入配置文件
            ObjectMapper objectMapper = new ObjectMapper();
            File outputFile = new File("src/main/resources/endpoints.yml");
            try {
                objectMapper.writeValue(outputFile, endpoints);
                System.out.println("Endpoints exported to " + outputFile.getAbsolutePath());
            } catch (IOException e) {
                e.printStackTrace();
            }
        };
    }
}