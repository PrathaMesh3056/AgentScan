# REST API & Distributed Scan Architecture

AgentScan provides an optional REST API and asynchronous worker service designed for submitting, managing, and monitoring security scans programmatically.

---

## Architecture Overview

The API stack consists of three primary components:
1. **FastAPI Service**: Provides REST endpoints for scan job dispatch, status queries, and real-time Server-Sent Events (SSE).
2. **Redis Streams Task Queue**: Handles asynchronous scan job dispatch and worker coordination.
3. **PostgreSQL Database**: Persists tenant records, scan metadata, historical audit logs, and complete report findings.

```
                  ┌──────────────────────┐
                  │    HTTP Client /     │
                  │   CI/CD Pipeline     │
                  └──────────┬───────────┘
                             │
                      REST / JWT / SSE
                             │
                             ▼
                  ┌──────────────────────┐
                  │   FastAPI Service    │
                  │  (agentscan api)     │
                  └─────┬──────────┬─────┘
                        │          │
        Enqueue Scan Job│          │ Persist Metadata
                        ▼          ▼
            ┌──────────────┐    ┌──────────────┐
            │ Redis Streams│    │  PostgreSQL  │
            │  Task Queue  │    │  (Database)  │
            └──────┬───────┘    └──────────────┘
                   │
                   ▼
            ┌──────────────┐
            │ Scan Worker  │
            │  (Consumer)  │
            └──────────────┘
```

---

## Getting Started

### Prerequisites
- Docker and Docker Compose
- Optional: `uv` or `pip` with `agentscan[api]` dependencies

### 1. Start the Service Stack

A complete local deployment configuration is provided in `docker-compose.api.yml`:

```bash
docker compose -f docker-compose.api.yml up -d
```

This starts:
- **API Server**: Listening on `http://localhost:8080`
- **PostgreSQL**: Port `5432`
- **Redis**: Port `6379`

Interactive OpenAPI documentation is available at `http://localhost:8080/docs`.

---

## Authentication

All scan endpoints require a tenant-scoped Bearer token. In development, a pre-shared key (PSK) can be exchanged for a JWT token.

### Requesting a Token

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/token \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "default-tenant",
    "secret": "dev-psk"
  }' | jq -r .access_token)

echo "Bearer Token: $TOKEN"
```

---

## API Endpoints

### 1. Enqueue a Scan Job

Submit a target URL or configuration for asynchronous scanning:

```bash
curl -s -X POST http://localhost:8080/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://localhost:8000/chat",
    "scan_mode": "SCAN"
  }'
```

**Response (`202 Accepted`):**
```json
{
  "scan_id": "scan_01h7abc123def",
  "status": "QUEUED",
  "created_at": "2026-09-20T12:00:00Z"
}
```

### 2. Stream Live Scan Progress (SSE)

Subscribe to Server-Sent Events to receive real-time execution events as attack modules run:

```bash
curl -N http://localhost:8080/scans/scan_01h7abc123def/stream \
  -H "Authorization: Bearer $TOKEN"
```

**Event Stream Format:**
```
event: progress
data: {"module": "ATK-001", "status": "running", "percent": 15}

event: finding
data: {"severity": "HIGH", "title": "Prompt Injection Detected", "owasp_id": "LLM01"}

event: complete
data: {"scan_id": "scan_01h7abc123def", "status": "COMPLETED", "score": 85}
```

### 3. Retrieve Scan Results

Poll the final report, findings summary, and risk score:

```bash
curl -s http://localhost:8080/scans/scan_01h7abc123def \
  -H "Authorization: Bearer $TOKEN"
```

**Response (`200 OK`):**
```json
{
  "scan_id": "scan_01h7abc123def",
  "target_url": "http://localhost:8000/chat",
  "status": "COMPLETED",
  "score": 85,
  "findings_count": 2,
  "findings": [
    {
      "id": "ATK-001",
      "severity": "HIGH",
      "title": "Direct Prompt Injection",
      "owasp_id": "LLM01",
      "remediation": "Enforce strict system prompt boundaries and input validation."
    }
  ]
}
```

---

## Configuration & Environment Variables

When deploying the API service, configure the following environment variables:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://postgres:postgres@localhost:5432/agentscan` |
| `REDIS_URL` | Redis connection string for stream queue | `redis://localhost:6379/0` |
| `API_SECRET_KEY` | Secret key used for signing JWT tokens | `dev-secret-key-change-in-production` |
| `WORKER_CONCURRENCY` | Maximum concurrent scans per worker | `4` |
