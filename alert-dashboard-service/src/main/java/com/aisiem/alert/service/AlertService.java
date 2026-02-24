package com.aisiem.alert.service;

import com.aisiem.alert.domain.Alert;
import com.aisiem.alert.domain.SecurityEvent;
import com.aisiem.alert.repository.AlertRepository;
import com.aisiem.alert.repository.SecurityEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class AlertService {

    private final SecurityEventRepository securityEventRepository;
    private final AlertRepository alertRepository;
    private final NotificationService notificationService;
    private final SimpMessagingTemplate messagingTemplate;

    /**
     * Periodically check for new security events and send alerts.
     * Runs every 30 seconds.
     */
    @Scheduled(fixedRate = 30000)
    public void processNewEvents() {
        List<SecurityEvent> newEvents = securityEventRepository.findNewEvents();

        if (!newEvents.isEmpty()) {
            log.info("Processing {} new security events", newEvents.size());
        }

        for (SecurityEvent event : newEvents) {
            if (shouldAlert(event)) {
                sendAlert(event);
            }
        }
    }

    private boolean shouldAlert(SecurityEvent event) {
        return "HIGH".equals(event.getSeverity()) || "CRITICAL".equals(event.getSeverity());
    }

    private void sendAlert(SecurityEvent event) {
        String message = String.format(
                "[AI SIEM ALERT] %s - %s\nSeverity: %s\nSource IP: %s\nDescription: %s\nDetected by: %s (confidence: %.1f%%)",
                event.getEventType(),
                event.getSeverity(),
                event.getSeverity(),
                event.getSourceIp(),
                event.getDescription(),
                event.getDetectedBy(),
                event.getConfidence() != null ? event.getConfidence() * 100 : 0.0
        );

        // 1. Send via webhook
        Alert webhookAlert = Alert.builder()
                .securityEventId(event.getId())
                .channel("WEBHOOK")
                .message(message)
                .build();
        notificationService.sendWebhook(webhookAlert);
        alertRepository.save(webhookAlert);

        // 2. Push via WebSocket to connected dashboards
        messagingTemplate.convertAndSend("/topic/alerts", Map.of(
                "eventId", event.getId(),
                "eventType", event.getEventType(),
                "severity", event.getSeverity(),
                "sourceIp", event.getSourceIp() != null ? event.getSourceIp() : "",
                "description", event.getDescription() != null ? event.getDescription() : "",
                "detectedBy", event.getDetectedBy(),
                "message", message
        ));

        // 3. Update event status
        event.setStatus("INVESTIGATING");
        securityEventRepository.save(event);

        log.info("Alert sent for event: id={}, type={}, severity={}", event.getId(), event.getEventType(), event.getSeverity());
    }
}
