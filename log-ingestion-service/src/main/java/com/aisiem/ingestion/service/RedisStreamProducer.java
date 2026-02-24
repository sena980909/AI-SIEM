package com.aisiem.ingestion.service;

import com.aisiem.ingestion.domain.LogEntry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.connection.stream.MapRecord;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class RedisStreamProducer {

    private static final String STREAM_KEY = "aisiem:logs";

    private final StringRedisTemplate redisTemplate;

    public void publishLog(LogEntry logEntry) {
        Map<String, String> logMap = new HashMap<>();
        logMap.put("id", logEntry.getId());
        logMap.put("timestamp", logEntry.getTimestamp().toString());
        logMap.put("source", logEntry.getSource());
        logMap.put("logLevel", logEntry.getLogLevel());
        logMap.put("message", logEntry.getMessage());
        logMap.put("sourceIp", logEntry.getSourceIp() != null ? logEntry.getSourceIp() : "");
        logMap.put("userId", logEntry.getUserId() != null ? logEntry.getUserId() : "");
        logMap.put("endpoint", logEntry.getEndpoint() != null ? logEntry.getEndpoint() : "");
        logMap.put("method", logEntry.getMethod() != null ? logEntry.getMethod() : "");
        logMap.put("statusCode", logEntry.getStatusCode() != null ? String.valueOf(logEntry.getStatusCode()) : "");

        MapRecord<String, String, String> record = MapRecord.create(STREAM_KEY, logMap);
        redisTemplate.opsForStream().add(record);

        log.debug("Published log to Redis Stream: id={}", logEntry.getId());
    }
}
