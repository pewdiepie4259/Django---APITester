# APIHub Changelog

All notable changes to the APIHub API Testing Platform project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-10-04 (Phase 8 Production Release)

### Added & Verified
- **Production-Ready Configuration & Hardening**:
  - Refactored `apihub/settings.py` to support environment-driven configuration (`DJANGO_SECRET_KEY`, `DJANGO_DEBUG`, `DJANGO_ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, `DATABASE_URL`).
  - Configured PostgreSQL fallback database router and production security headers (`SECURE_HSTS_SECONDS`, `X_FRAME_OPTIONS`, `SECURE_CONTENT_TYPE_NOSNIFF`).
- **Comprehensive Final Audit & Code Cleanup**:
  - Full codebase audit across models, views, templates, static assets, CLI, and database migrations (`makemigrations --check` returned 0 pending changes).
  - Verified 100% server-side authorization and IDOR protection across multi-tenant workspaces.
  - Verified SSRF protection (`_is_safe_url()`), secret redaction (`[REDACTED]`), and Personal Access Token hashing (`token_hash`).
- **Test Suite & Verification Sign-Off**:
  - Passed 100% of the 24 regression unit and integration tests (`python manage.py test client`).
  - Passed static asset compilation (`python manage.py collectstatic --noinput`).
- **APIHub Smart Assistant Panel & Utilities**:
  - Dual-mode developer assistant: Smart Local Analysis (default) & server-side AI provider integration.
  - HTTP Status Explainer (17 codes), JSON Schema & OpenAPI 3.0 schema generation, multi-language code export (cURL, Python, JS, Go, PHP, Java).
  - Structural Request/Response/OpenAPI diffing tools and Workspace Quality Health Diagnostics.
- **Isolated Presentation Demo Mode**:
  - Isolated synthetic demo workspace (`is_demo=True`) with 9-step interactive guided walkthrough.

---

## [0.6.0] — Phase 6 Collaboration & Developer Ecosystem

### Added
- Team Workspaces, Workspace Memberships, RBAC roles (OWNER, ADMIN, EDITOR, VIEWER).
- Personal Access Tokens (PAT) and Service Accounts for headless CI/CD authentication (`Bearer ahp_...`).
- Signed Webhook notifications (`X-APIHub-Signature`) with HMAC SHA256.
- CI/CD test run recording and JUnit/JSON test report outputs for GitHub Actions & GitLab CI.

---

## [0.5.0] — Phase 5 Advanced API Engineering

### Added
- OpenAPI 3.0 / Swagger import and export (JSON and YAML).
- Contract testing validation engine verifying mandatory fields, types, and content-types.
- Reusable Test Suites with sequential execution and stop-on-failure controls.
- Server-side API Health Monitoring with automated latency checks and alert deduplication.
- Public read-only Shareable API Documentation with secret redaction.
- Simulated Mock API endpoints (`/api/mock/<key>/`).

---

## [0.4.0] — Phase 4 Production Readiness & Security

### Added
- User Registration, Login, Logout, Profile, and Account settings.
- Security hardening: SSRF mitigation (`_is_safe_url`), CSRF protection, and audit logging (`AuditLog`).
- Health and readiness probes (`/health/`, `/ready/`).
- Secret redaction for sensitive headers (`Authorization`, `Cookie`, `X-API-Key`).

---

## [0.3.0] — Phase 3 API Testing & Workspace

### Added
- Automated Test Assertions (Status Code, Response Time, Header, Body Contains, JSON Path).
- Collection Runner for batch request execution.
- cURL import and export.
- Postman Collection v2.1 import and export.
- Analytics dashboard tracking success rates and response time distributions.

---

## [0.2.0] — Phase 2 API Workspace & Environments

### Added
- Collections and Saved Requests hierarchy.
- Environments and Environment Variables with `{{variable}}` substitution engine.
- Multiple request tab management.
- Request history tracking with status filtering.

---

## [0.1.0] — Phase 1 Modern Developer UI/UX

### Added
- Complete modern dark developer-tool UI redesign with Tailwind CSS and JetBrains Mono typography.
