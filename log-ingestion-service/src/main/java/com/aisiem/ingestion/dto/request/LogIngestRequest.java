package com.aisiem.ingestion.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LogIngestRequest {

    @NotBlank(message = "source is required")
    private String source;

    private String logLevel;

    @NotBlank(message = "message is required")
    private String message;

    private String sourceIp;

    private String userId;

    private String endpoint;

    private String method;

    private Integer statusCode;

    private String rawData;
}
