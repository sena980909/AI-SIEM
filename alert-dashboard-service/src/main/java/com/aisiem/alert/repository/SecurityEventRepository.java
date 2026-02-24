package com.aisiem.alert.repository;

import com.aisiem.alert.domain.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {

    List<SecurityEvent> findByStatus(String status);

    List<SecurityEvent> findByEventType(String eventType);

    List<SecurityEvent> findBySeverity(String severity);

    @Query("SELECT e FROM SecurityEvent e WHERE e.status = 'NEW' ORDER BY e.createdAt DESC")
    List<SecurityEvent> findNewEvents();

    @Query("SELECT e.eventType, COUNT(e) FROM SecurityEvent e WHERE e.createdAt >= :since GROUP BY e.eventType")
    List<Object[]> countByEventTypeSince(LocalDateTime since);

    @Query("SELECT e.severity, COUNT(e) FROM SecurityEvent e WHERE e.createdAt >= :since GROUP BY e.severity")
    List<Object[]> countBySeveritySince(LocalDateTime since);
}
