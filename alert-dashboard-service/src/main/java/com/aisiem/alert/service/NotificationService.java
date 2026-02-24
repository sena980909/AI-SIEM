package com.aisiem.alert.service;

import com.aisiem.alert.domain.Alert;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.Map;

@Service
@Slf4j
public class NotificationService {

    @Autowired(required = false)
    private JavaMailSender mailSender;

    @Value("${alert.webhook.url:}")
    private String webhookUrl;

    private final RestTemplate restTemplate = new RestTemplate();

    public void sendWebhook(Alert alert) {
        if (webhookUrl == null || webhookUrl.isBlank()) {
            log.debug("Webhook URL not configured, marking as SENT (local mode)");
            alert.setStatus("SENT");
            alert.setSentAt(LocalDateTime.now());
            return;
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            Map<String, String> body = Map.of("text", alert.getMessage());
            HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);

            restTemplate.postForEntity(webhookUrl, request, String.class);

            alert.setStatus("SENT");
            alert.setSentAt(LocalDateTime.now());
            log.info("Webhook sent for event: {}", alert.getSecurityEventId());
        } catch (Exception e) {
            alert.setStatus("FAILED");
            log.error("Webhook failed: {}", e.getMessage());
        }
    }

    public void sendEmail(Alert alert) {
        if (mailSender == null) {
            log.debug("Mail sender not configured, skipping email");
            alert.setStatus("SKIPPED");
            return;
        }

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(alert.getRecipient());
            message.setSubject("[AI SIEM] Security Alert");
            message.setText(alert.getMessage());

            mailSender.send(message);

            alert.setStatus("SENT");
            alert.setSentAt(LocalDateTime.now());
            log.info("Email sent to: {}", alert.getRecipient());
        } catch (Exception e) {
            alert.setStatus("FAILED");
            log.error("Email failed: {}", e.getMessage());
        }
    }
}
