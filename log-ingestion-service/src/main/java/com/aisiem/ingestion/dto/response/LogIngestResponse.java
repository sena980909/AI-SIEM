package com.aisiem.ingestion.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

@Getter
@Builder
@AllArgsConstructor
public class LogIngestResponse {

    private String id;
    private String source;
    private Instant timestamp;
    private String status;

    public static LogIngestResponse success(String id, String source, Instant timestamp) {
        return LogIngestResponse.builder()
                .id(id)
                .source(source)
                .timestamp(timestamp)
                .status("INGESTED")
                .build();
    }
}
