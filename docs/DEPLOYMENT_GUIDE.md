# APIHub — Production Deployment Guide

This guide details step-by-step instructions for deploying APIHub to production environments using **Django 5.2**, **Gunicorn**, **PostgreSQL**, and **Nginx**.

---

## 1. Prerequisites & Environment Setup

Ensure the host machine has the following software installed:
- **Python 3.11+**
- **PostgreSQL 14+**
- **Nginx** (optional, recommended reverse proxy)
- **Git**

```bash
# Clone the repository
git clone https://github.com/pewdiepie4259/Django---APITester.git
cd Django---APITester

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install production dependencies
pip install -r requirements.txt
```

---

## 2. Environment Variables Configuration

Copy `.env.example` to `.env` and populate all security values:

```bash
cp .env.example .env
```

### Production `.env` File Example

```ini
DJANGO_SECRET_KEY=c3f81e82a09b4d119c8f0e5b7a1d3c2e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=apihub.yourdomain.com,localhost,127.0.0.1
CSRF_TRUSTED_ORIGINS=https://apihub.yourdomain.com

# PostgreSQL Connection String
DATABASE_URL=postgresql://apihub_user:SuperSecurePassword123!@localhost:5432/apihub_db

# Security & SSL Settings
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
SECURE_HSTS_SECONDS=31536000
```

---

## 3. Database & Migrations Setup

1. **Create PostgreSQL Database & User**:
```sql
CREATE DATABASE apihub_db;
CREATE USER apihub_user WITH PASSWORD 'SuperSecurePassword123!';
GRANT ALL PRIVILEGES ON DATABASE apihub_db TO apihub_user;
```

2. **Execute Django Database Migrations**:
```bash
python manage.py migrate --settings=apihub.settings_prod
```

3. **Collect Static Files**:
```bash
python manage.py collectstatic --noinput --settings=apihub.settings_prod
```

---

## 4. Running Production WSGI Server (Gunicorn)

APIHub is served using Gunicorn WSGI HTTP Server.

```bash
gunicorn apihub.wsgi:application \
    --settings=apihub.settings_prod \
    --bind 0.0.0.0:8000 \
    --workers 4 \
    --threads 2 \
    --access-logfile - \
    --error-logfile -
```

---

## 5. Nginx Reverse Proxy & SSL Configuration

Configure Nginx as a reverse proxy with Let's Encrypt SSL certificate:

```nginx
server {
    listen 80;
    server_name apihub.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name apihub.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/apihub.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/apihub.yourdomain.com/privkey.pem;

    client_max_body_size 10M;

    location /static/ {
        alias /var/www/apihub/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, no-transform";
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 6. Health & Readiness Verification

Verify deployment health:
- **Health Check**: `GET /health/` -> `{"status": "ok", "service": "APIHub"}`
- **Readiness Check**: `GET /ready/` -> `{"status": "ready", "database": "connected"}`

---

## 7. Troubleshooting & Verification Commands

```bash
# Verify production settings checklist
python manage.py check --deploy --settings=apihub.settings_prod

# Execute automated test suite
python manage.py test
```
