# APIHub — Web-Based API Client & Testing Platform

![Django](https://img.shields.io/badge/Django-5.2-092E20?style=flat&logo=django)
![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python)
![Database](https://img.shields.io/badge/Database-SQLite%20%7C%20PostgreSQL-4169E1?style=flat&logo=postgresql)
![Tests](https://img.shields.io/badge/Tests-14%2F14%20Passing-brightgreen?style=flat)
![Security](https://img.shields.io/badge/Security-SSRF%20Protected%20%7C%20CSRF%20%7C%20Redacted%20Headers-indigo?style=flat)

APIHub is a modern, dark developer-tool API testing workspace and client built with **Django 5.2**, **HTML5**, **Tailwind CSS**, and **Vanilla JavaScript**. It serves as a CORS-bypass HTTP proxy and complete API testing suite featuring collections, environment variables, Postman import/export, automated test assertions, analytics, audit logging, user authentication, and data isolation.

---

## 🌟 Key Capabilities

### 🔐 Phase 4 — Production Readiness, Security & Auth
- **User Authentication**: Django session-based auth (Sign Up, Sign In, Sign Out, Profile & Settings).
- **User Data Isolation**: 100% server-side scope verification across Collections, Requests, Environments, History, and Test Runs.
- **SSRF & Security Hardening**: Server-side URL & DNS safety filter blocking private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`), loopback, and cloud metadata endpoints (`169.254.169.254`).
- **Secret Redaction**: Sensitive headers (`Authorization`, `Bearer`, `X-API-Key`, `Cookie`, `Secret`) are automatically redacted prior to history storage.
- **Audit Logging**: Comprehensive activity tracking via `AuditLog` model.
- **Production Configuration**: `apihub/settings_prod.py`, `.env.example`, `Procfile`, Gunicorn support, static files collection (`collectstatic`), and health endpoints (`/health/`, `/ready/`).

### 🧪 Phase 3 — API Testing, Import/Export & Analytics
- **Test Assertion Engine**: Status code validation, latency limits (`< 500ms`), string matching, and JSONPath evaluation.
- **Collection Runner**: Automated sequential test runner with summary metrics.
- **Import / Export**: Postman Collection (v2.1) import & export, single request JSON import/export.
- **Documentation Generator**: Auto-generates Markdown documentation for collections.
- **Request Analytics**: Executive dashboard displaying success rates, average latency, and status code distributions.

### 💼 Phase 2 — Workspace & Environment Management
- **Collections & Saved Requests**: Group endpoints into custom collections.
- **Environment Variables**: `{{variable}}` template string substitution across URLs, headers, params, and body.
- **Multiple Request Tabs**: Tabbed interface supporting parallel requests.

### 🎨 Phase 1 — Modern Dark Developer UI
- Sleek Linear/Vercel/Postman dark aesthetic with JetBrains Mono code typography.
- Response inspector with syntax highlighting, size tracking, and latency badges.
- Command Palette (`Ctrl+K` / `Cmd+K`) and keyboard shortcuts.

---

## 🚀 Quick Start (Local Development)

### 1. Clone & Setup Virtual Environment
```bash
git clone https://github.com/pewdiepie4259/Django---APITester.git
cd Django---APITester

python -m venv venv
# On Windows PowerShell:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Database Migrations
```bash
python manage.py migrate
```

### 4. Start Development Server
```bash
python manage.py runserver 127.0.0.1:8000
```
Open [http://127.0.0.1:8000/](http://127.0.0.1:8000/) in your browser to sign in or create an account.

---

## 🧪 Running Automated Tests

APIHub features a unit and integration test suite:

```bash
python manage.py test
```

---

## 📦 Production Deployment

For production deployment using **Gunicorn**, **PostgreSQL**, and **Nginx**:

```bash
# 1. Environment variables
cp .env.example .env

# 2. Collect Static Files
python manage.py collectstatic --noinput --settings=apihub.settings_prod

# 3. Run Gunicorn
gunicorn apihub.wsgi:application --settings=apihub.settings_prod --bind 0.0.0.0:8000
```

Refer to [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) for full deployment instructions.

---

## 📚 Documentation Index

- 📘 [Deployment Guide](docs/DEPLOYMENT_GUIDE.md)
- 🔒 [Security Specification](docs/SECURITY.md)
- 💾 [Backup & Recovery Plan](docs/BACKUP_AND_RECOVERY.md)
- 📄 [System Architecture](docs/03_SYSTEM_ARCHITECTURE.md)
- 📋 [Database & API Documentation](docs/04_DATABASE_AND_API_DOCUMENTATION.md)
- 🧪 [Test Plan & Report](docs/05_TEST_PLAN_AND_TEST_REPORT.md)
- 📖 [User & Developer Guide](docs/06_USER_AND_DEVELOPER_GUIDE.md)

---

## 📄 License

MIT License. Developed for API Hub testing and development platform.
