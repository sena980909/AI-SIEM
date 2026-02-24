# AI SIEM (Security Information and Event Management)

AI 기반 실시간 보안 로그 분석 시스템. MSA(Microservices Architecture) 구조로 로그 수집, 위협 탐지, 알림까지 자동화합니다.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Docker Compose                         │
│                                                             │
│  ┌──────────────┐    ┌─────────────┐    ┌────────────────┐  │
│  │ Log Ingest   │───>│   Redis     │───>│   Threat       │  │
│  │ Service      │    │   Streams   │    │   Detection    │  │
│  │ Spring Boot  │    │   (Queue)   │    │   FastAPI      │  │
│  │   :8081      │    │   :6379     │    │   :8082        │  │
│  └──────┬───────┘    └─────────────┘    └───────┬────────┘  │
│         │                                       │           │
│         ▼                                       ▼           │
│  ┌──────────────┐                      ┌────────────────┐   │
│  │ Elastic      │                      │   MySQL 8.0    │   │
│  │ Search 8.12  │                      │   :3306        │   │
│  │   :9200      │                      └───────┬────────┘   │
│  └──────────────┘                              │            │
│                                                ▼            │
│                                       ┌────────────────┐    │
│                                       │  Alert &       │    │
│                                       │  Dashboard     │    │
│                                       │  Spring Boot   │    │
│                                       │   :8083        │    │
│                                       └────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Tech Stack

| 구분 | 기술 |
|------|------|
| Log Ingestion | Java 17, Spring Boot 3.4.2 |
| Threat Detection | Python 3.13, FastAPI |
| Alert & Dashboard | Java 17, Spring Boot 3.4.2 |
| Message Queue | Redis 7 Streams |
| Log Storage | Elasticsearch 8.12 |
| RDB | MySQL 8.0 |
| LLM | Claude API / Ollama / None (환경변수로 전환) |
| Container | Docker Compose |
| Build | Gradle 8.12, pip |

## Services

### 1. Log Ingestion Service (:8081)

다양한 소스에서 발생하는 로그를 수집, Elasticsearch에 저장하고 Redis Stream으로 발행합니다.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/logs` | POST | 단건 로그 수집 |
| `/api/logs/batch` | POST | 배치 로그 수집 |
| `/api/logs/search/source/{source}` | GET | 소스별 검색 |
| `/api/logs/search/ip/{ip}` | GET | IP별 검색 |
| `/api/logs/search/level/{level}` | GET | 로그 레벨별 검색 |

### 2. Threat Detection Service (:8082)

Redis Stream에서 로그를 소비하여 룰 엔진 + LLM으로 보안 위협을 탐지합니다.

**탐지 시나리오:**

| 시나리오 | 조건 | 심각도 |
|----------|------|--------|
| Brute Force | 동일 IP에서 5분 내 로그인 실패 5회 이상 | HIGH |
| SQL Injection | 로그에서 SQL 공격 패턴 탐지 (`UNION SELECT`, `DROP TABLE` 등) | CRITICAL |
| Privilege Escalation | 비관리자가 `/admin/*` 접근 시도 (401/403) | HIGH |
| Anomaly Detection | LLM이 로그 패턴을 분석하여 이상 행동 판단 | MEDIUM~HIGH |

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/detection/events` | GET | 보안 이벤트 목록 (필터 지원) |
| `/api/detection/events/{id}` | GET | 이벤트 상세 조회 |
| `/api/detection/events/{id}/status` | PATCH | 이벤트 상태 변경 |
| `/api/detection/rules` | GET | 탐지 룰 목록 |

### 3. Alert & Dashboard Service (:8083)

탐지된 보안 이벤트를 30초 주기로 스캔하여 알림을 발송하고, 대시보드 통계 API를 제공합니다.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/dashboard/summary` | GET | 통계 요약 (타입별/심각도별) |
| `/api/dashboard/events` | GET | 이벤트 목록 (필터 지원) |
| `/api/dashboard/events/{id}` | GET | 이벤트 상세 |
| `/api/alerts` | GET | 알림 목록 |
| `/ws` | WebSocket | 실시간 알림 (STOMP) |

**알림 채널:** Webhook (Slack/Discord), Email (SMTP), WebSocket

## Quick Start

### 1. 환경 설정

```bash
cp .env.example .env
# .env 파일에서 필요한 값 수정
```

### 2. 인프라 실행

```bash
docker compose up -d mysql redis elasticsearch
```

### 3. 서비스 실행

```bash
# Log Ingestion Service
cd log-ingestion-service
./gradlew bootJar --no-daemon
java -jar build/libs/log-ingestion-service-0.0.1-SNAPSHOT.jar

# Threat Detection Service
cd threat-detection-service
python -m venv venv
source venv/Scripts/activate  # Windows
pip install -r requirements.txt
DB_PORT=3307 LLM_PROVIDER=none uvicorn app.main:app --port 8082

# Alert & Dashboard Service
cd alert-dashboard-service
./gradlew bootJar --no-daemon
java -jar build/libs/alert-dashboard-service-0.0.1-SNAPSHOT.jar
```

### 4. 테스트 로그 전송

```bash
# 단건 전송
curl -X POST http://localhost:8081/api/logs \
  -H "Content-Type: application/json" \
  -d '{
    "source": "web-server",
    "logLevel": "ERROR",
    "message": "SQL error: SELECT * FROM users WHERE id=1 OR 1=1;--",
    "sourceIp": "10.0.0.99",
    "endpoint": "/api/users",
    "method": "GET",
    "statusCode": 500
  }'

# 시뮬레이터로 대량 테스트
python tools/log_simulator.py --scenario all --count 100
```

### 5. 결과 확인

```bash
# 대시보드 통계
curl http://localhost:8083/api/dashboard/summary

# 탐지된 이벤트
curl http://localhost:8082/api/detection/events

# 발송된 알림
curl http://localhost:8083/api/alerts
```

## Log Simulator

공격 시뮬레이션 도구로 파이프라인을 테스트할 수 있습니다.

```bash
python tools/log_simulator.py --scenario all --count 100      # 전체 시나리오
python tools/log_simulator.py --scenario brute_force --count 20 # Brute Force만
python tools/log_simulator.py --scenario sql_injection --count 15
python tools/log_simulator.py --scenario mixed --count 200      # 혼합 트래픽
```

## LLM Provider 설정

환경변수 `LLM_PROVIDER`로 AI 분석 엔진을 전환할 수 있습니다.

| 환경 | 설정값 | 설명 |
|------|--------|------|
| 개발/클라우드 | `LLM_PROVIDER=claude` | Claude API 사용 |
| 폐쇄망/산업망 | `LLM_PROVIDER=ollama` | 로컬 Ollama (Llama3 등) |
| 룰셋만 사용 | `LLM_PROVIDER=none` | LLM 없이 룰 엔진만 동작 |

```bash
# Claude API
LLM_PROVIDER=claude CLAUDE_API_KEY=sk-... uvicorn app.main:app --port 8082

# Ollama (로컬)
LLM_PROVIDER=ollama OLLAMA_HOST=http://localhost:11434 uvicorn app.main:app --port 8082
```

## Swagger UI

| Service | URL |
|---------|-----|
| Log Ingestion | http://localhost:8081/swagger-ui.html |
| Threat Detection | http://localhost:8082/docs |
| Alert & Dashboard | http://localhost:8083/swagger-ui.html |

## Database Schema

```sql
detection_rule     -- 탐지 룰 정의 (4개 기본 룰 포함)
security_event     -- 탐지된 보안 이벤트
alert              -- 발송된 알림 기록
user               -- 관리자/분석가 계정
```

## Project Structure

```
AISIEM/
├── docker-compose.yml
├── .env.example
├── common/init-scripts/init-db.sql
│
├── log-ingestion-service/          # Spring Boot :8081
│   ├── controller/                 # LogIngestionController, LogSearchController
│   ├── service/                    # LogIngestionService, RedisStreamProducer
│   ├── domain/                     # LogEntry (ES Document)
│   └── dto/                        # Request/Response DTOs
│
├── threat-detection-service/       # FastAPI :8082
│   ├── api/                        # Detection API router
│   ├── service/
│   │   ├── rule_engine.py          # Brute Force, SQLi, PrivEsc 룰
│   │   ├── ai_analyzer.py          # Claude/Ollama LLM 분석
│   │   └── stream_consumer.py      # Redis Stream 소비자
│   ├── model/                      # SQLAlchemy models
│   └── schema/                     # Pydantic schemas
│
├── alert-dashboard-service/        # Spring Boot :8083
│   ├── controller/                 # AlertController, DashboardController
│   ├── service/                    # AlertService, NotificationService
│   ├── domain/                     # Alert, SecurityEvent (JPA)
│   └── global/config/              # WebSocket, Swagger
│
└── tools/
    └── log_simulator.py            # 공격 시뮬레이션 도구
```
