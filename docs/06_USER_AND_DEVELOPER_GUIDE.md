# User Manual & Developer Setup Guide — APIHub

## PART A — USER MANUAL

Welcome to **APIHub**, a web-based API testing platform inspired by Postman. This guide explains how to use APIHub to test REST APIs, manage authentication, inspect responses, and manage request history.

---

### 1. Opening APIHub
1. Launch your web browser (Chrome, Firefox, Edge, or Safari).
2. Navigate to `http://127.0.0.1:8000/`.
3. You will see the APIHub workspace consisting of:
   - **Top Navigation Bar**: Logo, CORS proxy status badge, quick template presets dropdown, search command palette trigger (`⌘K`), keyboard shortcuts trigger, and user profile avatar.
   - **Left Sidebar**: `+ New Request` action button, workspace section (`Collections`, `Environments`), history log with real-time filter input and bulk clear option.
   - **Breadcrumb & Request Execution Bar**: Compact HTTP method selector (color-coded), target URL input with instant clear `×`, and `SEND ↗` primary accent button (`Ctrl + Enter`).
   - **Request Configuration Tabs**: Params (sync with URL), Headers (with preset shortcuts), Authorization (No Auth, Bearer Token, Basic Auth), Body editor (with line numbers gutter, JSON format, and live syntax validation).
   - **Response Inspector**: Status metrics (color-coded status dot, execution latency ms, size KB), copy payload button, response tabs (`Pretty` syntax-highlighted, `Headers` grid, `Raw Text`).
   - **Command Palette (`Ctrl + K`)**: Modal search palette for fast command execution and preset loading.

---

### 2. Selecting HTTP Method
1. Click the method dropdown menu (default is **GET**).
2. Select your desired HTTP method:
   - **GET** (Green): Retrieve data from an API.
   - **POST** (Amber): Send new data to create a resource.
   - **PUT** (Blue): Replace or update an existing resource.
   - **PATCH** (Purple): Apply partial modifications to a resource.
   - **DELETE** (Rose): Remove a resource.
   - **HEAD** / **OPTIONS** (Slate): Retrieve headers or check supported options.

---

### 3. Entering API Endpoint URL
1. Click the URL input box (`#req-url`).
2. Type or paste your target API URL (e.g. `https://jsonplaceholder.typicode.com/posts/1`).
3. If you omit `http://` or `https://`, APIHub automatically prepends `https://`.

---

### 4. Adding Query Parameters
1. Select the **Params** tab below the URL bar.
2. Click **+ Add Parameter** to add a new parameter row.
3. Enter the **Key** (e.g. `page`) and **Value** (e.g. `2`).
4. Notice that query parameters automatically synchronize with the URL string in real-time.
5. Uncheck the checkbox beside a parameter row to temporarily disable it without deleting it.

---

### 5. Adding Headers
1. Select the **Headers** tab.
2. Click **+ Add Header** or click **+ JSON Header** to quickly inject `Content-Type: application/json`.
3. Enter custom header keys (e.g. `Accept`, `X-API-Key`) and values.

---

### 6. Configuring Authentication
1. Select the **Authorization** tab.
2. Choose your authentication mode:
   - **No Auth**: Default unauthenticated request.
   - **Bearer Token**: Enter your secret JWT or OAuth token string. APIHub automatically appends `Authorization: Bearer <token>` to request headers.
   - **Basic Auth**: Enter your username and password. APIHub encodes your credentials using Base64 HTTP Basic Authentication.

---

### 7. Adding Request Body
1. Select the **Body** tab.
2. Type or paste your JSON, XML, or text payload in the monospace editor.
3. Use the context helpers in the tab header:
   - **Format JSON**: Formats and indents your JSON payload cleanly.
   - **Sample JSON**: Inserts a sample JSON request payload.
   - **Clear**: Clears the body text editor.
4. Watch the real-time indicator (`✓ Valid JSON` vs `⚠ Raw Text / Invalid JSON`).

---

### 8. Dispatching Request
Click the **Send** button or press **`Ctrl + Enter`** (or **`Cmd + Enter`** on macOS).

During execution:
- The button displays a spinning indicator ("Sending...").
- A live execution timer measures latency in real-time.

---

### 9. Understanding the Response Inspector

Once the proxy request completes, the response panel updates automatically:

- **Status Badge**: Displays HTTP status code and status text (e.g., `200 OK`, `201 Created`, `404 Not Found`, `504 Gateway Timeout`). Color-coded for fast reading:
  - **2xx**: Green (Success)
  - **3xx**: Blue (Redirection)
  - **4xx**: Amber (Client Error)
  - **5xx**: Rose (Server Error)
- **Response Time**: Execution latency measured in milliseconds (`ms`).
- **Response Size**: Payload size measured in kilobytes (`KB`).

---

### 10. Response Viewing Modes
- **Response Body (Pretty)**: Default view. Pretty-prints JSON responses with syntax highlighting:
  - Keys: Light Blue
  - Strings: Light Green
  - Numbers: Yellow
  - Booleans: Pink
  - Nulls: Gray / Italic
- **Headers**: Interactive table listing all HTTP response headers returned by the target API.
- **Raw Text**: Plain text view of the response payload.

---

### 11. Copying Response Payload
Click the **Copy** button in the status bar to copy the entire formatted response body to your system clipboard.

---

### 12. Using Request History & Sidebar
1. Every executed request is automatically logged to the left sidebar history list.
2. **Search / Filter**: Type in the "Filter history..." input box to filter past requests by method, URL, or status code.
3. **Restore Request**: Click any history item card to restore its HTTP method, URL, parameters, headers, and body back into the active workspace.
4. **Clear History**: Click **Clear** in the history header to wipe all historical records.

---

### 13. Using Quick Template Presets
Click the **⚡ Quick Templates...** dropdown in the top header to instantly load working test requests for `JSONPlaceholder` or `HttpBin`.

---

### 14. Troubleshooting Matrix

| Problem | Cause | Solution |
| :--- | :--- | :--- |
| **"Please enter a target URL" Toast** | URL input field is empty | Enter a valid target endpoint URL before clicking Send. |
| **"Invalid JSON" Toast when clicking Format** | Body editor contains malformed JSON | Check for missing double quotes, trailing commas, or unclosed brackets. |
| **Status 504 Gateway Timeout** | Target server took over 15 seconds to respond | Verify target server status or host network connectivity. |
| **Status 502 Connection Error** | Invalid host domain or DNS resolution failed | Verify URL spelling and ensure the target host is reachable. |

---

## PART B — DEVELOPER SETUP & CONTRIBUTOR GUIDE

This section outlines instructions for setting up APIHub locally, managing migrations, running tests, and understanding project internals.

---

### 1. Prerequisites
- **Python**: Version 3.11.x installed and available on system PATH (`python --version`).
- **Git**: Version control system.
- **Web Browser**: Any modern web browser.

---

### 2. Project Setup & Installation Step-by-Step

#### Step 1: Clone or Open Workspace
Open a PowerShell or Terminal window in the project root directory:

```bash
cd f:\Django---APITester
```

#### Step 2: Create Virtual Environment
Create a Python virtual environment named `venv`:

```bash
python -m venv venv
```

#### Step 3: Activate Virtual Environment
- **Windows (PowerShell)**:
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
- **Linux / macOS**:
  ```bash
  source venv/bin/activate
  ```

#### Step 4: Install Required Dependencies
Install Django and Python Requests library:

```bash
python -m pip install django requests
```

---

### 3. Database Initialization & Migrations

APIHub uses an SQLite database (`db.sqlite3`). Apply database migrations to create the `client_requesthistory` table:

```bash
python manage.py migrate
```

Output should confirm successful migration execution:
```text
Operations to perform:
  Apply all migrations: admin, auth, client, contenttypes, sessions
Running migrations:
  Applying contenttypes.0001_initial... OK
  Applying auth.0001_initial... OK
  ...
  Applying client.0001_initial... OK
  Applying sessions.0001_initial... OK
```

---

### 4. Running Automated Tests

Run the Django automated unit test suite to verify project health:

```bash
python manage.py test
```

Expected output:
```text
Creating test database for alias 'default'...
...
----------------------------------------------------------------------
Ran 3 tests in 0.034s

OK
Destroying test database for alias 'default'...
```

---

### 5. Running Development Server

Start the local Django development web server:

```bash
python manage.py runserver 127.0.0.1:8000
```

Open your browser and navigate to:
`http://127.0.0.1:8000/`

---

### 6. Architecture & Directory Overview

```text
Django---APITester/
├── apihub/                  # Django project root configuration
│   ├── settings.py          # App configuration & database settings
│   ├── urls.py              # Global URL routing dispatcher
│   ├── wsgi.py              # WSGI application entry point
│   └── asgi.py              # ASGI application entry point
├── client/                  # Main application package
│   ├── models.py            # RequestHistory database ORM model
│   ├── views.py             # Proxy dispatching & history API controllers
│   ├── urls.py              # App-level routing rules
│   ├── tests.py             # Unit test suite
│   └── templates/
│       └── client/
│           └── index.html   # Single-Page App UI template (Tailwind + JS)
├── db.sqlite3               # SQLite database file
├── manage.py                # Django CLI management executable
└── venv/                    # Isolated Python virtual environment
```

---

### 7. Core Views & Logic Explained

#### A. Outbound Proxy Execution (`client/views.py`)
The `execute_request` view receives JSON from frontend via `POST /api/execute/`:

```python
@csrf_exempt
@require_http_methods(["POST"])
def execute_request(request):
    payload = json.loads(request.body.decode('utf-8') or '{}')
    method = (payload.get('method') or 'GET').strip().upper()
    url = (payload.get('url') or '').strip()
    
    # Prepend http:// if missing
    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'https://' + url
        
    clean_headers = _normalize_key_values(payload.get('headers', {}))
    clean_params = _normalize_key_values(payload.get('params', {}))
    
    # Execute outbound call with 15s timeout
    resp = requests.request(
        method=method,
        url=url,
        headers=clean_headers,
        params=clean_params,
        data=send_data,
        auth=req_auth,
        timeout=15,
        allow_redirects=True,
    )
```

---

### 8. Debugging & Common Tasks

- **Inspect SQLite Records**: Use Python shell to inspect saved history:
  ```bash
  python manage.py shell
  ```
  ```python
  from client.models import RequestHistory
  print(RequestHistory.objects.count())
  for item in RequestHistory.objects.all()[:5]:
      print(item)
  ```
- **Reset Database**: To reset database state, delete `db.sqlite3` and re-run `python manage.py migrate`.
