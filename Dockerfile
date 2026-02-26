# OWASPGuard - Python API + React frontend
FROM node:22-alpine AS frontend
WORKDIR /build
COPY OWASPGuard/frontend/package*.json ./
RUN npm install
COPY OWASPGuard/frontend ./
RUN npm run build

FROM python:3.11-slim
WORKDIR /app

# Install git for GitHub repo cloning
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY OWASPGuard/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY OWASPGuard/ ./OWASPGuard/
COPY --from=frontend /build/dist ./OWASPGuard/frontend/dist

ENV PYTHONPATH=/app
EXPOSE 8000

# Render sets PORT; default 8000 for local
CMD ["sh", "-c", "uvicorn OWASPGuard.api.server:app --host 0.0.0.0 --port ${PORT:-8000}"]
