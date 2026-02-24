package com.aisiem.alert.controller;

import com.aisiem.alert.domain.Alert;
import com.aisiem.alert.repository.AlertRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/alerts")
@RequiredArgsConstructor
@Tag(name = "Alerts", description = "Alert management endpoints")
public class AlertController {

    private final AlertRepository alertRepository;

    @GetMapping
    @Operation(summary = "List all alerts")
    public ResponseEntity<List<Alert>> listAlerts(
            @RequestParam(required = false) String status) {
        if (status != null) {
            return ResponseEntity.ok(alertRepository.findByStatus(status));
        }
        return ResponseEntity.ok(alertRepository.findAll());
    }

    @GetMapping("/event/{eventId}")
    @Operation(summary = "Get alerts for a specific security event")
    public ResponseEntity<List<Alert>> getAlertsByEvent(@PathVariable Long eventId) {
        return ResponseEntity.ok(alertRepository.findBySecurityEventId(eventId));
    }
}
