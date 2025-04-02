package com.skygeo.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
public class EndpointExporter {

    @Autowired
    @Qualifier("requestMappingHandlerMapping")  // 指定使用 WebMVC 的 HandlerMapping
    private RequestMappingHandlerMapping handlerMapping;

    @Bean
    public ApplicationRunner exportEndpoints() {
        return args -> {
            try {
                // 获取所有端点映射
                Map<String, String> endpoints = handlerMapping.getHandlerMethods().entrySet().stream()
                        .collect(Collectors.toMap(
                                entry -> entry.getKey().toString(),
                                entry -> entry.getValue().getMethod().toGenericString()
                        ));

                // 将输出文件路径改为项目根目录
                Path outputPath = Paths.get("endpoints.yml");

                // 将端点写入配置文件
                ObjectMapper objectMapper = new ObjectMapper();
                objectMapper.writeValue(outputPath.toFile(), endpoints);

                System.out.println("Endpoints exported to " + outputPath.toAbsolutePath());
            } catch (IOException e) {
                System.err.println("An error occurred while exporting endpoints: " + e.getMessage());
            } catch (Exception e) {
                System.err.println("Unexpected error: " + e.getMessage());
            }
        };
    }
}