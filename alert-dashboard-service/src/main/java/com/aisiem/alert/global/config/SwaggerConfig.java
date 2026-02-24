package com.aisiem.alert.global.config;

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
                        .title("AI SIEM - Alert & Dashboard Service")
                        .description("Alert management and monitoring dashboard API")
                        .version("v1.0.0"));
    }
}
