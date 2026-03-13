FROM python:3.12-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer cache)
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app source
COPY app/ .

# Create dirs for reports and logs
RUN mkdir -p /app/reports /app/logs

EXPOSE 8000

# Use gunicorn + uvicorn worker class for production multi-process ASGI.
# uvicorn --workers is deprecated in standalone mode; gunicorn manages the
# process lifecycle correctly and keeps WebSocket + asyncio event loops isolated.
CMD ["gunicorn", "api:app", \
     "-k", "uvicorn.workers.UvicornWorker", \
     "--workers", "2", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "120", \
     "--graceful-timeout", "30", \
     "--keep-alive", "5", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
