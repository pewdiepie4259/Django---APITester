# APIHub — Technical Documentation Index

Welcome to the official documentation suite for **APIHub**, a lightweight, web-based API testing platform inspired by Postman, built with Django, Tailwind CSS, and Vanilla JavaScript.

This documentation hub contains comprehensive product specifications, architectural designs, API references, test reports, and guidebooks for users and developers.

---

## 📑 Document Directory

| Document # | Document Title | Description & Target Audience |
| :--- | :--- | :--- |
| [**01_PRD.md**](file:///f:/Django---APITester/docs/01_PRD.md) | **Product Requirements Document** | High-level vision, problem statement, user personas, scope boundaries, and detailed functional requirements distinguishing implemented features from future roadmap. |
| [**02_SRS.md**](file:///f:/Django---APITester/docs/02_SRS.md) | **Software Requirements Specification** | Formal IEEE-style software requirements specification, outlining precise inputs, outputs, system constraints, and non-functional requirements (FR-01 to FR-15). |
| [**03_SYSTEM_ARCHITECTURE.md**](file:///f:/Django---APITester/docs/03_SYSTEM_ARCHITECTURE.md) | **System Architecture & Design** | Deep-dive technical design, Mermaid architectural diagrams, backend request proxy execution flows, component responsibilities, and security models. |
| [**04_DATABASE_AND_API_DOCUMENTATION.md**](file:///f:/Django---APITester/docs/04_DATABASE_AND_API_DOCUMENTATION.md) | **Database & API Reference** | Data models (`RequestHistory`), Mermaid ER diagrams, internal endpoints (`/api/execute/`, `/api/history/`), and external proxy handling specifications. |
| [**05_TEST_PLAN_AND_TEST_REPORT.md**](file:///f:/Django---APITester/docs/05_TEST_PLAN_AND_TEST_REPORT.md) | **Test Plan & Test Report** | Strategy for unit, integration, and UI testing, along with a comprehensive test matrix and verified automated Django test suite execution results. |
| [**06_USER_AND_DEVELOPER_GUIDE.md**](file:///f:/Django---APITester/docs/06_USER_AND_DEVELOPER_GUIDE.md) | **User & Developer Guide** | End-to-end user manual for API testing workflows, alongside developer setup, database migration, environment setup, and deployment guides. |

---

## 🏗️ Repository Architecture Summary

```text
Django---APITester/
├── apihub/                  # Django Project Configuration
│   ├── asgi.py              # ASGI interface entry point
│   ├── settings.py          # Global project configuration & installed apps
│   ├── urls.py              # Root URL routing configuration
│   └── wsgi.py              # WSGI interface entry point
├── client/                  # Core Application Module
│   ├── admin.py             # Django admin registration
│   ├── apps.py              # Client app configuration
│   ├── models.py            # RequestHistory database model & serializers
│   ├── views.py             # Proxy engine, CORS bypass, and history API endpoints
│   ├── urls.py              # Client view route mappings
│   ├── tests.py             # Automated unit and integration test suite
│   └── templates/
│       └── client/
│           └── index.html   # Single-Page Application UI (Tailwind CSS + JS)
├── docs/                    # Official Project Documentation
│   ├── README.md            # Master documentation index (this file)
│   ├── 01_PRD.md            # Product Requirements Document
│   ├── 02_SRS.md            # Software Requirements Specification
│   ├── 03_SYSTEM_ARCHITECTURE.md
│   ├── 04_DATABASE_AND_API_DOCUMENTATION.md
│   ├── 05_TEST_PLAN_AND_TEST_REPORT.md
│   └── 06_USER_AND_DEVELOPER_GUIDE.md
├── db.sqlite3               # SQLite database instance
├── manage.py                # Django CLI management script
└── README.md                # Repository root overview
```

---

## 🔍 Empirically Verified Implementation Status

- **Framework & Core**: Django `5.2.17` running on Python `3.11.9`.
- **Database Engine**: SQLite 3 (`db.sqlite3`).
- **Test Suite Status**: **7 / 7 Automated Tests Passing** (`0.053s` execution latency).
- **Backend Workspace & Proxy Status**: Active on `http://127.0.0.1:8000/` with outbound proxying, CORS bypass, Collections CRUD, Saved Requests, Environment Variables (`{{variable}}`), Multiple Tabs, Command Palette (`Ctrl+K`), and real-time history logging.
