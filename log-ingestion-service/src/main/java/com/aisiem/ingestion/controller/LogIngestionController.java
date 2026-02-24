package com.aisiem.ingestion.controller;

import com.aisiem.ingestion.dto.request.LogBatchRequest;
import com.aisiem.ingestion.dto.request.LogIngestRequest;
import com.aisiem.ingestion.dto.response.LogIngestResponse;
import com.aisiem.ingestion.service.LogIngestionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/logs")
@RequiredArgsConstructor
@Tag(name = "Log Ingestion", description = "Log collection and ingestion endpoints")
public class LogIngestionController {

    private final LogIngestionService logIngestionService;

    @PostMapping
    @Operation(summary = "Ingest a single log entry")
    public ResponseEntity<LogIngestResponse> ingestLog(@Valid @RequestBody LogIngestRequest request) {
        LogIngestResponse response = logIngestionService.ingestLog(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/batch")
    @Operation(summary = "Ingest multiple log entries at once")
    public ResponseEntity<List<LogIngestResponse>> ingestBatch(@Valid @RequestBody LogBatchRequest request) {
        List<LogIngestResponse> responses = logIngestionService.ingestBatch(request.getLogs());
        return ResponseEntity.status(HttpStatus.CREATED).body(responses);
    }
}
