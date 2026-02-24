package com.aisiem.alert.controller;

import com.aisiem.alert.domain.SecurityEvent;
import com.aisiem.alert.repository.SecurityEventRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
@Tag(name = "Dashboard", description = "Dashboard and statistics endpoints")
public class DashboardController {

    private final SecurityEventRepository securityEventRepository;

    @GetMapping("/summary")
    @Operation(summary = "Get dashboard summary statistics")
    public ResponseEntity<Map<String, Object>> getSummary(
            @RequestParam(defaultValue = "24") int hours) {

        // Use UTC to match MySQL Docker container timezone
        LocalDateTime since = LocalDateTime.now(ZoneOffset.UTC).minusHours(hours);

        Map<String, Object> summary = new HashMap<>();
        summary.put("period_hours", hours);
        summary.put("total_events", securityEventRepository.count());

        // Events by type
        Map<String, Long> byType = new HashMap<>();
        for (Object[] row : securityEventRepository.countByEventTypeSince(since)) {
            byType.put((String) row[0], (Long) row[1]);
        }
        summary.put("events_by_type", byType);

        // Events by severity
        Map<String, Long> bySeverity = new HashMap<>();
        for (Object[] row : securityEventRepository.countBySeveritySince(since)) {
            bySeverity.put((String) row[0], (Long) row[1]);
        }
        summary.put("events_by_severity", bySeverity);

        return ResponseEntity.ok(summary);
    }

    @GetMapping("/events")
    @Operation(summary = "List security events with filters")
    public ResponseEntity<List<SecurityEvent>> listEvents(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) String severity) {

        if (status != null) {
            return ResponseEntity.ok(securityEventRepository.findByStatus(status));
        }
        if (eventType != null) {
            return ResponseEntity.ok(securityEventRepository.findByEventType(eventType));
        }
        if (severity != null) {
            return ResponseEntity.ok(securityEventRepository.findBySeverity(severity));
        }
        return ResponseEntity.ok(securityEventRepository.findAll());
    }

    @GetMapping("/events/{id}")
    @Operation(summary = "Get security event detail")
    public ResponseEntity<SecurityEvent> getEvent(@PathVariable Long id) {
        return securityEventRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}
