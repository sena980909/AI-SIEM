package com.aisiem.ingestion.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.elasticsearch.annotations.DateFormat;
import org.springframework.data.elasticsearch.annotations.Document;
import org.springframework.data.elasticsearch.annotations.Field;
import org.springframework.data.elasticsearch.annotations.FieldType;

import java.time.Instant;

@Document(indexName = "aisiem-logs")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LogEntry {

    @Id
    private String id;

    @Field(type = FieldType.Date, format = DateFormat.epoch_millis)
    private Instant timestamp;

    @Field(type = FieldType.Keyword)
    private String source;

    @Field(type = FieldType.Keyword)
    private String logLevel;

    @Field(type = FieldType.Text)
    private String message;

    @Field(type = FieldType.Keyword)
    private String sourceIp;

    @Field(type = FieldType.Keyword)
    private String userId;

    @Field(type = FieldType.Keyword)
    private String endpoint;

    @Field(type = FieldType.Keyword)
    private String method;

    @Field(type = FieldType.Integer)
    private Integer statusCode;

    @Field(type = FieldType.Text)
    private String rawData;
}
