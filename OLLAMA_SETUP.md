# 🤖 AI Vulnerability Analyzer — Setup Guide

Powered by **Ollama + Llama3 8B** — 100% free, local, no cloud APIs, no API keys.

---

## What the AI Does

After each security scan completes, the AI analyzer automatically:

1. **Explains each vulnerability** in plain English
2. **Assesses severity** independently
3. **Provides exploit scenarios** — concrete examples of how an attacker would use the finding
4. **Generates remediation steps** — specific, actionable fixes
5. **Writes an executive summary** — suitable for a CISO or engineering lead
6. **Identifies OWASP categories** for each finding

All of this appears in the **HTML and JSON reports** and is accessible via the REST API at `GET /scans/{id}/ai`.

---

## Step 1 — Install Ollama

### macOS
```bash
brew install ollama
# or download from https://ollama.com/download
```

### Linux
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### Windows
Download the installer from: https://ollama.com/download/windows

---

## Step 2 — Pull the Llama3 Model

```bash
ollama pull llama3
```

This downloads the **Llama3 8B** model (~4.7 GB). It only needs to be done once.

Optional — faster/smaller model for low-RAM machines:
```bash
ollama pull llama3:8b-instruct-q4_0   # ~4 GB, good quality
```

Optional — larger model for higher quality analysis:
```bash
ollama pull llama3:70b                 # ~40 GB, requires 64 GB RAM or GPU
```

---

## Step 3 — Start Ollama

```bash
ollama serve
```

Ollama will listen on `http://localhost:11434`.

To verify it's running:
```bash
curl http://localhost:11434/api/tags
```

You should see your downloaded models listed.

---

## Step 4 — Start the AI Worker

### Option A — Docker Compose (recommended)

```bash
# Start core services + AI worker
docker compose --profile ai up -d

# Verify the AI worker is running
docker compose ps ai-worker
```

### Option B — Run AI worker locally (development)

```bash
cd app
OLLAMA_BASE_URL=http://localhost:11434 \
OLLAMA_MODEL=llama3 \
celery -A celery_app worker --concurrency=1 -Q ai -n ai-worker@local
```

---

## Step 5 — Configure Environment

In your `.env` file:

```bash
# AI / Ollama configuration
OLLAMA_BASE_URL=http://host.docker.internal:11434   # Docker → host
OLLAMA_MODEL=llama3                                  # or llama3:70b etc.
OLLAMA_TIMEOUT=120                                   # seconds (CPU is slow)
OLLAMA_MAX_TOKENS=1024                               # tokens per response
```

> **Note:** `host.docker.internal` is the magic hostname that lets Docker containers reach the host machine's Ollama. On Linux you may need `172.17.0.1` instead.

---

## Step 6 — Verify AI is Working

Check the health endpoint:
```bash
curl -s https://localhost/health | python3 -m json.tool
```

You should see:
```json
{
  "status": "ok",
  "ai": {
    "available": true,
    "model": "llama3",
    "backend": "ollama"
  }
}
```

---

## Using the AI Analysis API

### Get AI analysis for a scan
```bash
curl -s https://localhost/scans/{scan_id}/ai \
  -H "x-api-key: $SCANNER_API_KEY" | python3 -m json.tool
```

### Retry AI analysis (if Ollama was down during scan)
```bash
curl -s -X POST https://localhost/scans/{scan_id}/ai/retry \
  -H "x-api-key: $SCANNER_API_KEY"
```

### Example AI analysis response
```json
{
  "status": "completed",
  "scan_id": "abc123",
  "ai_available": true,
  "model_used": "llama3",
  "executive_summary": {
    "executive_summary": "The target API exposes critical SQL injection vulnerabilities...",
    "risk_headline": "API is at immediate risk of full database compromise.",
    "priority_actions": [
      "Immediately patch SQL injection in /api/users endpoint",
      "Rotate all database credentials",
      "Enable WAF with SQLi rules"
    ],
    "overall_risk_rating": "CRITICAL"
  },
  "findings_analysis": {
    "FINDING_ID": {
      "explanation": "The /api/users endpoint is vulnerable to SQL injection...",
      "risk": "An attacker can dump the entire database, including user credentials...",
      "exploit_example": "GET /api/users?id=1' UNION SELECT username,password FROM users--",
      "remediation": [
        "Use parameterized queries or prepared statements",
        "Implement input validation and allowlisting",
        "Apply principle of least privilege on DB accounts"
      ],
      "severity_assessment": "CRITICAL — direct SQL injection with no authentication required",
      "owasp_reference": "OWASP API Security Top 10 2023 - API8: Security Misconfiguration",
      "model_used": "llama3",
      "analysis_time_ms": 4200
    }
  }
}
```

---

## Performance Notes

| Hardware | Llama3 8B speed | Notes |
|----------|----------------|-------|
| CPU only (8-core) | ~30–90s per finding | Acceptable for post-scan analysis |
| Apple M1/M2/M3 | ~5–15s per finding | Fast, recommended |
| NVIDIA GPU (VRAM ≥ 8 GB) | ~2–8s per finding | Fastest |

The AI worker processes findings **asynchronously** — scans complete immediately and AI analysis runs in the background. The scanner never waits for AI.

---

## Graceful Degradation

If Ollama is not installed or not running:

- ✅ Scans run normally
- ✅ HTML/JSON reports are generated normally
- ✅ A note appears in reports: *"AI analysis unavailable — install Ollama"*
- ✅ `GET /scans/{id}/ai` returns `{"ai_available": false}`
- ✅ No errors, no crashes

To enable AI later, install Ollama and call `POST /scans/{id}/ai/retry`.

---

## Optional — Managed Ollama Container

Instead of installing Ollama on the host, you can run it as a Docker container:

```bash
docker compose --profile ollama --profile ai up -d

# Pull the model inside the container
docker compose exec ollama ollama pull llama3
```

> **GPU passthrough:** Uncomment the `deploy.resources` section in `docker-compose.yml` for NVIDIA GPU acceleration.

---

## Troubleshooting

**AI worker starts but analysis always shows `ai_available: false`**
```bash
# Verify Ollama is reachable from the worker container
docker compose exec ai-worker curl http://host.docker.internal:11434/api/tags
```

**Analysis is very slow**
```bash
# Check if GPU is being used
ollama ps   # shows active model and hardware
```

**`ollama pull` fails**
```bash
# Check disk space (model is ~4.7 GB)
df -h
```

**Linux: `host.docker.internal` doesn't resolve**
```bash
# Add to .env:
OLLAMA_BASE_URL=http://172.17.0.1:11434
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                  Docker Stack                       │
│                                                     │
│  FastAPI ──► Celery scan worker ──► Redis           │
│     │                │                │             │
│     │         (scan completes)        │             │
│     │                │                │             │
│     │                └──► AI Worker ──┘             │
│     │                        │                      │
│     │              (ai_analysis:{scan_id})          │
│     │                                               │
└─────┼───────────────────────────────────────────────┘
      │                        │
      ▼                        ▼
   REST API              Host Machine
GET /scans/{id}/ai    Ollama (port 11434)
                      └── llama3 model
```

AI tasks run in a **dedicated Celery queue** (`ai`) so they never compete with security scanning tasks.
