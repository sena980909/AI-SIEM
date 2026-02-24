package com.aisiem.alert.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "security_event")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "log_entry_id")
    private String logEntryId;

    @Column(name = "event_type", nullable = false, length = 50)
    private String eventType;

    @Column(nullable = false, length = 20)
    private String severity;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "source_ip", length = 45)
    private String sourceIp;

    @Column(name = "detected_by", nullable = false, length = 20)
    private String detectedBy;

    @Column(name = "rule_id")
    private Long ruleId;

    private Double confidence;

    @Column(length = 30)
    private String status;

    @Column(name = "raw_log", columnDefinition = "TEXT")
    private String rawLog;

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}
