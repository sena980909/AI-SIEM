package com.aisiem.ingestion.repository;

import com.aisiem.ingestion.domain.LogEntry;
import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

@Repository
public interface LogEntryRepository extends ElasticsearchRepository<LogEntry, String> {

    List<LogEntry> findBySource(String source);

    List<LogEntry> findBySourceIpAndTimestampBetween(String sourceIp, Instant from, Instant to);

    List<LogEntry> findByLogLevel(String logLevel);
}
