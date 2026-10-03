# APIHub — Web-Based API Client & Tester

A lightweight, polished web-based API testing platform inspired by Postman, built with **Django**, **Tailwind CSS**, and **Vanilla JavaScript**.

APIHub acts as an HTTP proxy/dispatcher to bypass browser CORS restrictions and securely test REST APIs directly from your web browser.

---

## Features

- **CORS Bypass Proxy**: Backend dispatcher built with Python `requests` executes outbound calls securely without browser CORS limitations.
- **Color-Coded HTTP Methods**: GET (green), POST (amber), PUT (blue), PATCH (purple), DELETE (rose).
- **Dynamic Configuration Tabs**:
  - **Query Parameters**: Key-value rows with two-way sync with the URL bar.
  - **Headers**: Dynamic key-value row generator with preset shortcuts (e.g. JSON content type).
  - **Authorization**: Supports No Auth, Bearer Token, and Basic Auth.
  - **Body**: Monospace editor with real-time JSON validation indicator, "Format JSON", and sample payloads.
- **Response Inspector**:
  - Live execution latency (measured via `time.perf_counter()`), size in KB, and color-coded status badges.
  - Formatted JSON response with syntax highlighting for keys, strings, numbers, booleans, and nulls.
  - Structured response headers table and raw text views.
  - One-click "Copy Response" to clipboard.
- **Request History**:
  - Persisted in SQLite database (`RequestHistory` model).
  - Search/filter past requests by URL, method, or status code.
  - Click any history item to restore parameters, headers, body, and URL into the active editor.
- **Quick Templates**: One-click presets for JSONPlaceholder and HTTPBin endpoints.
- **Keyboard Shortcuts**: `Ctrl + Enter` (or `Cmd + Enter`) to dispatch requests instantly.

---

## Quick Start

### 1. Install Dependencies
```bash
pip install django requests
```

### 2. Run Database Migrations
```bash
python manage.py migrate
```

### 3. Start Development Server
```bash
python manage.py runserver
```

Open [http://127.0.0.1:8000/](http://127.0.0.1:8000/) in your browser.

---

## Testing

Run unit tests:
```bash
python manage.py test
```