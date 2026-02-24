-- AI SIEM Database Initialization
-- Shared tables used by multiple services

CREATE DATABASE IF NOT EXISTS aisiem_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE aisiem_db;

-- ========== Detection Rules ==========
CREATE TABLE IF NOT EXISTS detection_rule (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    event_type VARCHAR(50) NOT NULL COMMENT 'BRUTE_FORCE, SQL_INJECTION, PRIVILEGE_ESCALATION, ANOMALY',
    pattern TEXT NOT NULL COMMENT 'Regex or condition pattern',
    severity VARCHAR(20) NOT NULL COMMENT 'LOW, MEDIUM, HIGH, CRITICAL',
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- ========== Security Events ==========
CREATE TABLE IF NOT EXISTS security_event (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    log_entry_id VARCHAR(255) COMMENT 'Elasticsearch document ID',
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    source_ip VARCHAR(45),
    detected_by VARCHAR(20) NOT NULL COMMENT 'RULE or AI',
    rule_id BIGINT NULL,
    confidence DOUBLE DEFAULT 0.0 COMMENT 'AI confidence score 0.0 ~ 1.0',
    status VARCHAR(30) DEFAULT 'NEW' COMMENT 'NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE',
    raw_log TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (rule_id) REFERENCES detection_rule(id) ON DELETE SET NULL
);

-- ========== Alerts ==========
CREATE TABLE IF NOT EXISTS alert (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    security_event_id BIGINT NOT NULL,
    channel VARCHAR(20) NOT NULL COMMENT 'EMAIL, WEBHOOK, SLACK',
    recipient VARCHAR(255),
    message TEXT,
    status VARCHAR(20) DEFAULT 'PENDING' COMMENT 'PENDING, SENT, FAILED',
    sent_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (security_event_id) REFERENCES security_event(id) ON DELETE CASCADE
);

-- ========== Users (Admin/Analyst) ==========
CREATE TABLE IF NOT EXISTS user (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    role VARCHAR(20) DEFAULT 'ANALYST' COMMENT 'ADMIN, ANALYST',
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- ========== Default Detection Rules ==========
INSERT INTO detection_rule (name, description, event_type, pattern, severity) VALUES
('Brute Force Login', '5+ failed logins from same IP within 5 minutes', 'BRUTE_FORCE', 'login_failed >= 5 AND time_window <= 300', 'HIGH'),
('SQL Injection Attempt', 'SQL injection patterns in request parameters', 'SQL_INJECTION', '(''\\s*(OR|AND)\\s+[''0-9]|UNION\\s+SELECT|DROP\\s+TABLE|;\\s*--)', 'CRITICAL'),
('Privilege Escalation', 'Non-admin user accessing admin endpoints', 'PRIVILEGE_ESCALATION', 'role != ADMIN AND path LIKE /admin/%', 'HIGH'),
('Anomaly Detection', 'AI-detected abnormal behavior pattern', 'ANOMALY', 'ai_confidence >= 0.8', 'MEDIUM');

-- Default admin user (password: admin123 - BCrypt encoded)
INSERT INTO user (username, password, email, role) VALUES
('admin', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'admin@aisiem.local', 'ADMIN');
