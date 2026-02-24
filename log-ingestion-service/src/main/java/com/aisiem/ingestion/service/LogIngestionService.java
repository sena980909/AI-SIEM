package com.aisiem.ingestion.service;

import com.aisiem.ingestion.domain.LogEntry;
import com.aisiem.ingestion.dto.request.LogIngestRequest;
import com.aisiem.ingestion.dto.response.LogIngestResponse;
import com.aisiem.ingestion.repository.LogEntryRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class LogIngestionService {

    private final LogEntryRepository logEntryRepository;
    private final RedisStreamProducer redisStreamProducer;

    public LogIngestResponse ingestLog(LogIngestRequest request) {
        LogEntry logEntry = LogEntry.builder()
                .timestamp(Instant.now())
                .source(request.getSource())
                .logLevel(request.getLogLevel() != null ? request.getLogLevel() : "INFO")
                .message(request.getMessage())
                .sourceIp(request.getSourceIp())
                .userId(request.getUserId())
                .endpoint(request.getEndpoint())
                .method(request.getMethod())
                .statusCode(request.getStatusCode())
                .rawData(request.getRawData())
                .build();

        // 1. Save to Elasticsearch
        LogEntry saved = logEntryRepository.save(logEntry);
        log.info("Log ingested: id={}, source={}", saved.getId(), saved.getSource());

        // 2. Publish to Redis Stream for threat detection
        redisStreamProducer.publishLog(saved);

        return LogIngestResponse.success(saved.getId(), saved.getSource(), saved.getTimestamp());
    }

    public List<LogIngestResponse> ingestBatch(List<LogIngestRequest> requests) {
        return requests.stream()
                .map(this::ingestLog)
                .toList();
    }
}
