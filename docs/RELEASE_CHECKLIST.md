# APIHub Release Checklist — v1.0.0

This document outlines the mandatory release and deployment verification steps prior to launching APIHub v1.0.0.

---

## 1. Pre-Release Source Code Audit
- [x] **Centralized Versioning**: Verify `APIHUB_VERSION = '1.0.0'` in `apihub/settings.py`.
- [x] **Static Code Checks**: Run Django system check:
  ```bash
  python manage.py check
  python manage.py check --deploy
  ```
- [x] **Unused Imports & Dead Code**: Perform static analysis scan and clean up unused modules.
- [x] **Documentation Accuracy**: Verify README, CHANGELOG.md, and System Architecture docs match actual code implementation.

---

## 2. Comprehensive Test & Quality Verification
- [x] **Full Automated Test Suite**: Run all Django unit and integration tests:
  ```bash
  python manage.py test client
  ```
  *Target*: 100% pass rate across authentication, RBAC, proxy execution, assertions, contract testing, OpenAPI import/export, monitors, webhooks, intelligence endpoints, and diff utilities.
- [x] **End-to-End Workflow Verification**: Verify complete path:
  `Register -> Login -> Create Workspace -> Create Collection -> Create Environment -> Create Request -> Execute Proxy -> Add Assertions -> Run Tests -> Generate Schema -> Generate Code -> View Health -> Export Collection`.

---

## 3. Security & Privacy Audit
- [x] **SSRF Protection**: Verify `_is_safe_url()` blocks loopback (`127.0.0.1`, `localhost`), link-local (`169.254.169.254`), and private RFC 1918 IP addresses.
- [x] **Secret Redaction**: Ensure passwords, Bearer tokens, PATs, and environment secrets are redacted as `[REDACTED]` or `{{token}}` in logs, public documentation, code generation, and AI analysis payloads.
- [x] **AI Privacy & Safety**: Confirm AI provider calls happen server-side only with secret redaction. Never send unredacted credentials to external LLM providers.
- [x] **CSRF & XSS Protection**: Verify Django `CsrfViewMiddleware` is active on HTML forms and JSON body inputs are sanitized.
- [x] **Demo Mode Isolation**: Confirm Demo Mode workspace (`is_demo=True`) never executes real external API calls, never uses real credentials, and never fires production webhooks.

---

## 4. Database & Migration Verification
- [x] **Database Migrations**: Ensure all migrations are applied cleanly:
  ```bash
  python manage.py makemigrations
  python manage.py migrate
  ```
- [x] **Database Constraints & Indexes**: Verify foreign key cascading, unique constraints (PAT hashes, webhook secrets, public share keys), and indexing on `(user, -timestamp)` and `(user, collection)`.

---

## 5. Deployment & Production Configuration
- [x] **Environment Variables**: Configure mandatory environment variables:
  - `SECRET_KEY`: High-entropy production key
  - `DEBUG`: Set to `False` in production
  - `ALLOWED_HOSTS`: Configured for production domain
  - `DATABASE_URL`: PostgreSQL connection string (if using PostgreSQL)
  - `AI_PROVIDER` & `AI_API_KEY`: Optional external AI provider
- [x] **Static File Collection**: Gather static assets:
  ```bash
  python manage.py collectstatic --noinput
  ```
- [x] **WSGI / ASGI Server**: Configure Gunicorn / Uvicorn worker threads behind Nginx reverse proxy.

---

## 6. Post-Deployment Smoke Tests
- [x] Check `/health/` returns `{"status": "ok"}` (200 OK).
- [x] Check `/ready/` returns `{"status": "ready"}` (200 OK).
- [x] Verify SPA main view (`/`) loads cleanly and Smart Assistant panel initializes in Local Analysis Mode.
