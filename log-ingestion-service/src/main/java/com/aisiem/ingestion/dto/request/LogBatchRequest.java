package com.aisiem.ingestion.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class LogBatchRequest {

    @NotEmpty(message = "logs must not be empty")
    @Valid
    private List<LogIngestRequest> logs;
}
