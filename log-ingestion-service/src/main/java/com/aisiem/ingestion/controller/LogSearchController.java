package com.aisiem.ingestion.controller;

import com.aisiem.ingestion.domain.LogEntry;
import com.aisiem.ingestion.repository.LogEntryRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;

@RestController
@RequestMapping("/api/logs/search")
@RequiredArgsConstructor
@Tag(name = "Log Search", description = "Search and query stored logs")
public class LogSearchController {

    private final LogEntryRepository logEntryRepository;

    @GetMapping("/source/{source}")
    @Operation(summary = "Search logs by source")
    public ResponseEntity<List<LogEntry>> searchBySource(@PathVariable String source) {
        return ResponseEntity.ok(logEntryRepository.findBySource(source));
    }

    @GetMapping("/ip/{sourceIp}")
    @Operation(summary = "Search logs by source IP within a time range")
    public ResponseEntity<List<LogEntry>> searchByIp(
            @PathVariable String sourceIp,
            @RequestParam Instant from,
            @RequestParam Instant to) {
        return ResponseEntity.ok(logEntryRepository.findBySourceIpAndTimestampBetween(sourceIp, from, to));
    }

    @GetMapping("/level/{level}")
    @Operation(summary = "Search logs by log level")
    public ResponseEntity<List<LogEntry>> searchByLevel(@PathVariable String level) {
        return ResponseEntity.ok(logEntryRepository.findByLogLevel(level));
    }
}
