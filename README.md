# AI SIEM (Security Information and Event Management)

AI 기반 실시간 보안 로그 분석 시스템. MSA(Microservices Architecture) 구조로 로그 수집, 위협 탐지, 알림까지 자동화합니다.

---

## 빠른 시작 (Quick Start)

### 1단계: 환경 설정

```bash
git clone <repo-url> && cd AISIEM
cp .env.example .env
# .env 파일에서 OPENAI_API_KEY 등 필요한 값 수정 (없으면 룰 엔진만 동작)
```

### 2단계: 전체 실행 (Docker 한 방)

```bash
docker compose up -d --build
```

> 7개 컨테이너가 자동으로 뜹니다 (MySQL, Redis, Elasticsearch, 3개 앱 서비스, Grafana)

### 3단계: 접속

| URL | 설명 |
|-----|------|
| http://localhost:8083 | **SIEM 대시보드** - 실시간 모니터링 UI |
| http://localhost:3000 | **Grafana** - 운영 모니터링 (admin / aisiem) |
| http://localhost:8081/swagger-ui.html | Log Ingestion API 문서 |
| http://localhost:8082/docs | Threat Detection API 문서 |
| http://localhost:8083/swagger-ui.html | Alert & Dashboard API 문서 |

### 4단계: 테스트 로그 주입

```bash
# 시뮬레이터로 공격 트래픽 생성
python tools/log_simulator.py --scenario all --count 100

# 또는 단건 수동 전송
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
```

### 5단계: 결과 확인

- http://localhost:8083 새로고침 → 차트/테이블에 탐지 결과 표시
- WebSocket 실시간 알림 피드 자동 수신
- http://localhost:3000 → Grafana에서 시계열 그래프 확인

```bash
# API로도 확인 가능
curl http://localhost:8083/api/dashboard/summary    # 대시보드 통계
curl http://localhost:8082/api/detection/events      # 탐지된 이벤트
curl http://localhost:8083/api/alerts                # 발송된 알림
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Docker Compose                              │
│                                                                      │
│  ┌──────────────┐    ┌─────────────┐    ┌────────────────┐           │
│  │ Log Ingest   │───>│   Redis     │───>│   Threat       │           │
│  │ Service      │    │   Streams   │    │   Detection    │           │
│  │ Spring Boot  │    │   (Queue)   │    │   FastAPI      │           │
│  │   :8081      │    │   :6379     │    │   :8082        │           │
│  └──────┬───────┘    └─────────────┘    └───────┬────────┘           │
│         │                                       │                    │
│         ▼                                       ▼                    │
│  ┌──────────────┐                      ┌────────────────┐            │
│  │ Elastic      │                      │   MySQL 8.0    │            │
│  │ Search 8.12  │◄─────┐              │   :3306        │            │
│  │   :9200      │      │              └───────┬────────┘            │
│  └──────────────┘      │                      │                     │
│                        │                      ▼                     │
│                 ┌──────┴───────┐      ┌────────────────┐            │
│                 │  Grafana     │      │  Alert &       │            │
│                 │  :3000       │◄─────│  Dashboard     │            │
│                 └──────────────┘      │  + SIEM UI     │            │
│                                       │  Spring Boot   │            │
│                                       │   :8083        │            │
│                                       └────────────────┘            │
└──────────────────────────────────────────────────────────────────────┘
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
| LLM | OpenAI GPT-4o mini / Claude API / Ollama / None (환경변수로 전환) |
| Monitoring | Grafana 10.4 |
| Dashboard UI | HTML + Tailwind CSS + Chart.js + WebSocket |
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

## 개별 서비스 실행 (Docker 없이)

인프라(MySQL, Redis, ES)만 Docker로 띄우고 앱 서비스를 로컬에서 직접 실행할 수도 있습니다.

```bash
# 인프라만 실행
docker compose up -d mysql redis elasticsearch

# Log Ingestion Service
cd log-ingestion-service && ./gradlew bootRun

# Threat Detection Service
cd threat-detection-service
python -m venv venv && source venv/Scripts/activate
pip install -r requirements.txt
DB_PORT=3307 uvicorn app.main:app --port 8082

# Alert & Dashboard Service
cd alert-dashboard-service && ./gradlew bootRun
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
| 가성비 추천 | `LLM_PROVIDER=openai` | GPT-4o mini (~$0.0004/분석) |
| 정밀 분석 | `LLM_PROVIDER=claude` | Claude Haiku 3.5 (~$0.003/분석) |
| 폐쇄망/산업망 | `LLM_PROVIDER=ollama` | 로컬 LLM (Qwen, Llama3 등) |
| 룰셋만 사용 | `LLM_PROVIDER=none` | LLM 없이 룰 엔진만 동작 |

```bash
# OpenAI GPT-4o mini (가성비 추천)
LLM_PROVIDER=openai OPENAI_API_KEY=sk-proj-... uvicorn app.main:app --port 8082

# Claude API
LLM_PROVIDER=claude CLAUDE_API_KEY=sk-ant-... uvicorn app.main:app --port 8082

# 로컬 LLM (llama-server / Ollama)
LLM_PROVIDER=ollama OLLAMA_HOST=http://localhost:11434 uvicorn app.main:app --port 8082
```

## E2E Test Results

3개 LLM 모델로 동일한 이상 트래픽을 분석한 결과, **모두 10/10 탐지 성공**했습니다.

| 항목 | Qwen 7B (로컬) | GPT-4o mini | Claude Haiku 3.5 |
|------|---------------|-------------|-----------------|
| 탐지율 | 10/10 | 10/10 | 10/10 |
| CRITICAL 판정 | 0건 | 0건 | 4건 |
| 비용/분석 | 무료 | ~$0.0004 | ~$0.003 |
| 적합 환경 | 폐쇄망/산업망 | 가성비 클라우드 | 정밀 분석 |

> 상세 테스트 리포트: [aitest.md](./aitest.md)

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
│   │   ├── ai_analyzer.py          # OpenAI/Claude/Ollama LLM 분석
│   │   └── stream_consumer.py      # Redis Stream 소비자
│   ├── model/                      # SQLAlchemy models
│   └── schema/                     # Pydantic schemas
│
├── alert-dashboard-service/        # Spring Boot :8083
│   ├── controller/                 # AlertController, DashboardController
│   ├── service/                    # AlertService, NotificationService
│   ├── domain/                     # Alert, SecurityEvent (JPA)
│   ├── global/config/              # WebSocket, Swagger
│   └── resources/static/index.html # SIEM 대시보드 UI
│
├── grafana/provisioning/           # Grafana 자동 설정 :3000
│   ├── datasources/datasources.yml # MySQL + ES 데이터소스
│   └── dashboards/json/            # 대시보드 JSON (6개 패널)
│
├── tools/
│   └── log_simulator.py            # 공격 시뮬레이션 도구
├── test_attack_simulator.py        # E2E 공격 테스트 스크립트
└── aitest.md                       # AI 탐지 테스트 리포트
```
