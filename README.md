# Vulnexus AI Scanner API (SaaS Edition)

Professional API Security Scanner with SaaS-ready multi-tenant architecture.

## Features
- **Advanced Engine**: Async scanning using `httpx` and `asyncio`.
- **Modular Vulnerability Analyzers**: SQLi, XSS, Command Injection, SSRF, JWT, and more.
- **SaaS Integration**: Full integration with Supabase (Auth + DB).
- **Asynchronous Processing**: Background scans via Celery and Redis.
- **Production Ready**: Rate limiting, security headers, and Railway deployment support.

## Architecture
- `app/api.py`: FastAPI entry point.
- `app/routes/`: Modular endpoints (Auth, Scans, Projects).
- `app/services/`: Core logic (Engine, Analyzer, Payloads).
- `app/workers/`: Background task processing.

## Local Setup
1. `pip install -r requirements.txt`
2. Configure `.env` using `.env.example`.
3. `uvicorn app.api:app --reload`
4. Start worker: `celery -A app.workers.celery_worker worker --loglevel=info`

## Deployment
See [DEPLOYMENT_SAAS.md](DEPLOYMENT_SAAS.md) for Railway and Supabase instructions.
