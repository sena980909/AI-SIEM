package com.aisiem.ingestion.global.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("AI SIEM - Log Ingestion Service")
                        .description("Log collection, parsing, and storage service")
                        .version("v1.0.0"));
    }
}
