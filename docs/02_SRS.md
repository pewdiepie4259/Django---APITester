# Software Requirements Specification (SRS) — APIHub

## 1. Introduction

### 1.1 Purpose
This Software Requirements Specification (SRS) document defines the detailed functional, non-functional, and system requirements for **APIHub — Web-Based API Testing Platform & Proxy Dispatcher**. Built following IEEE 830 standards, this document serves as the technical baseline for developers, system architects, and software evaluators.

### 1.2 Scope
APIHub is a web application that enables developers to construct HTTP requests, dispatch them through a server-side Django proxy engine to bypass browser CORS restrictions, inspect structured response payloads, and maintain request history in a local SQLite database.

### 1.3 Definitions, Acronyms, and Abbreviations
- **API**: Application Programming Interface
- **CORS**: Cross-Origin Resource Sharing
- **HTTP**: Hypertext Transfer Protocol
- **JSON**: JavaScript Object Notation
- **OR**: Object-Relational Mapper (Django ORM)
- **REST**: Representational State Transfer
- **SPA**: Single-Page Application
- **SOP**: Same-Origin Policy
- **SRS**: Software Requirements Specification
- **UI/UX**: User Interface / User Experience

### 1.4 Document Convention
- Requirement IDs follow the format **FR-XX** for Functional Requirements and **NFR-XX** for Non-Functional Requirements.
- Operational priority is denoted as High, Medium, or Low.

---

## 2. Overall Description

### 2.1 Product Perspective
APIHub operates as a self-contained, lightweight web application. It acts as an intermediary bridge between a developer's web browser and external target REST API servers:

```text
+-------------------+      JSON Proxy Payload      +-----------------------+      Outbound HTTP      +------------------------+
|  Browser Frontend |  ------------------------->  | Django Proxy Backend  |  -------------------->  |   External Target API  |
|  (Tailwind + JS)  |  <-------------------------  | (Python requests)     |  <--------------------  |  (e.g., jsonplaceholder|
+-------------------+     Parsed JSON Response     +-----------------------+     Target Response     +------------------------+
                                                               |
                                                       Persists | RequestHistory
                                                               v
                                                       +-------------------+
                                                       | SQLite Database   |
                                                       +-------------------+
```

### 2.2 Product Functions
1. **HTTP Method Configuration**: Select between GET, POST, PUT, PATCH, DELETE, HEAD, and OPTIONS.
2. **Dynamic Query & Header Management**: Interactive table rows with real-time URL two-way binding.
3. **Authentication Dispatch**: Support for Bearer Token injection and Basic Authentication encoding.
4. **JSON Body Management**: Text area with real-time JSON validation, syntax formatting, and sample insertion.
5. **Proxy Execution Engine**: Backend request execution using Python `requests` with CORS bypass and 15s timeout limit.
6. **Response Inspection**: Live display of HTTP status, latency (ms), content size (KB), color-coded JSON syntax highlighting, raw view, and header grid.
7. **History Logging & Restoration**: SQLite database persistence of past requests with search filter, click-to-restore, and bulk deletion.
8. **Template Presets**: Pre-configured sample requests for instant testing.
9. **Global Shortcuts**: `Ctrl + Enter` / `Cmd + Enter` dispatch trigger.

### 2.3 User Classes and Characteristics
- **Web Application Developers**: Highly technical users requiring exact header control, custom request bodies, and fast response copying.
- **API Integrators & QA Engineers**: Users needing history search, request restoration, and precise status code / timing verification.

### 2.4 Operating Environment
- **Operating System**: Cross-platform (Windows, macOS, Linux).
- **Backend Runtime**: Python 3.11+ with Django 5.2 and `requests` package.
- **Browser Compatibility**: Chrome 90+, Firefox 88+, Edge 90+, Safari 14+.

### 2.5 Design and Implementation Constraints
- **Framework Constraint**: Must utilize standard Django MVT structure (Model, View, Template).
- **Security Constraint**: Must run proxy operations safely with `@csrf_exempt` on `/api/execute/` and `/api/history/`.
- **Database Constraint**: Must store history records in SQLite using Django ORM (`RequestHistory` model).

### 2.6 Assumptions and Dependencies
- Python 3.11 environment with internet connectivity.
- Tailwind CSS loaded via CDN (`https://cdn.tailwindcss.com`).
- Google Fonts (`Inter`, `JetBrains Mono`) accessible over HTTP/HTTPS.

---

## 3. Specific Functional Requirements

### FR-01: Request Method Selection
- **ID**: FR-01
- **Description**: The system shall allow the user to select an HTTP request method from a dropdown menu.
- **Supported Methods**: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`.
- **Input**: User selection via dropdown selector `#req-method`.
- **Processing**: Frontend updates method state and dynamically applies method-specific color themes (Green for GET, Amber for POST, Blue for PUT, Purple for PATCH, Rose for DELETE).
- **Output**: Visual method badge update in UI.
- **Expected Behavior**: Selected method is included in the outgoing proxy JSON payload.
- **Error Conditions**: None. Defaults to `GET` if unspecified.

### FR-02: URL Input
- **ID**: FR-02
- **Description**: The system shall provide an input field for the target API URL.
- **Input**: Text string entered into `#req-url` (e.g. `https://jsonplaceholder.typicode.com/posts/1`).
- **Processing**: On frontend, automatically parses query parameters if `?` is present. On backend (`views.py`), verifies scheme presence; if missing, prepends `https://`.
- **Output**: Validated absolute URL string.
- **Expected Behavior**: Cleaned URL is dispatched to proxy.
- **Error Conditions**: If URL input is empty when clicking Send, system displays a toast warning `"Please enter a target URL"` and aborts execution.

### FR-03: Query Parameter Management
- **ID**: FR-03
- **Description**: The system shall provide a dynamic table to manage key-value query parameters.
- **Input**: User clicks `+ Add Parameter` or edits parameter key/value inputs.
- **Processing**: 
  - `syncParamsToUrl()`: Reads active enabled parameter rows and appends them to URL string.
  - `updateParamsFromUrl()`: Parses URL query parameters and generates input rows.
- **Output**: Synchronized URL string and parameter count badge (`#params-badge`).
- **Expected Behavior**: Parameters with unchecked enable boxes or empty keys are excluded from final request.
- **Error Conditions**: Malformed URL characters are safely escaped using `encodeURIComponent` / `URLSearchParams`.

### FR-04: Header Management
- **ID**: FR-04
- **Description**: The system shall allow users to add, enable/disable, and remove custom HTTP headers.
- **Input**: Key-value rows in `#headers-table` or click `+ JSON Header` preset button.
- **Processing**: `_normalize_key_values()` in Django views processes header array into a Python dictionary.
- **Output**: Headers dictionary passed to `requests.request()`.
- **Expected Behavior**: Disabled rows (`enabled: false`) are filtered out before dispatch.
- **Error Conditions**: Duplicate header keys are overwritten by the latest entry in normalized dictionary.

### FR-05: Authentication
- **ID**: FR-05
- **Description**: The system shall support customizable authentication modes.
- **Input**: Select auth type (`none`, `bearer`, `basic`). Token string for Bearer; Username/Password for Basic.
- **Processing**:
  - `bearer`: Appends `Authorization: Bearer <token>` to headers.
  - `basic`: Constructs `HTTPBasicAuth(username, password)` instance for `requests`.
- **Output**: Authenticated outgoing HTTP request.
- **Expected Behavior**: Credentials properly formatted before making outbound call.
- **Error Conditions**: Empty credentials result in standard unauthenticated dispatch.

### FR-06: Request Body Management
- **ID**: FR-06
- **Description**: The system shall provide a raw body editor for JSON/text payloads.
- **Input**: Text entered into `#req-body` textarea.
- **Processing**:
  - Frontend: `validateJsonInput()` verifies valid JSON syntax and updates status indicator (`✓ Valid JSON` vs `⚠ Raw Text`). `formatJsonBody()` formats JSON string with 2-space indentation.
  - Backend: Encodes string to UTF-8 bytes; automatically sets `Content-Type: application/json` if body is JSON object/list and header is absent.
- **Output**: Encoded request payload for `POST`, `PUT`, `PATCH`, `DELETE` operations.
- **Expected Behavior**: Valid JSON formatted cleanly on command.
- **Error Conditions**: Clicking "Format JSON" on invalid JSON triggers an error toast `"Invalid JSON: <error>"`.

### FR-07: Request Execution (Backend Proxy)
- **ID**: FR-07
- **Description**: The Django backend shall execute external HTTP requests via `execute_request` view.
- **Input**: POST request to `/api/execute/` with JSON payload `{ method, url, headers, params, auth, body }`.
- **Processing**: `views.py` calls `requests.request()` with `timeout=15` seconds. Measures wall-clock execution time via `time.perf_counter()`.
- **Output**: JSON object `{ status_code, status_text, time_ms, size_kb, headers, data, is_json, history_id }`.
- **Expected Behavior**: Outbound request executes on target server bypassing browser CORS.
- **Error Conditions**:
  - Timeout: Returns status `504` with text `'Gateway Timeout (15s)'`.
  - Connection Failure: Returns status `502` with text `'Connection Error'`.
  - Internal Error: Returns status `500` with text `'Internal Error'`.

### FR-08: Response Processing
- **ID**: FR-08
- **Description**: The system shall process target HTTP responses into structured JSON payloads.
- **Input**: Outbound `requests.Response` object.
- **Processing**: Evaluates response content. Attempts `resp.json()`. If parsing succeeds, sets `is_json = True`. Otherwise, captures `resp.text` with `is_json = False`. Calculates size in KB (`len(content) / 1024.0`).
- **Output**: Formatted response payload delivered to client.
- **Expected Behavior**: Correct distinction between JSON APIs and raw HTML/text endpoints.
- **Error Conditions**: Non-UTF8 binary text fallback handled gracefully.

### FR-09: Response Display
- **ID**: FR-09
- **Description**: The frontend shall render status metrics, syntax-highlighted JSON, headers, and raw text.
- **Input**: Proxy response JSON object.
- **Processing**: `renderResponse()` populates status badge, time badge, size badge, headers table, raw text view, and colorized HTML string generated by `syntaxHighlightJson()`.
- **Output**: Visual response inspector panels.
- **Expected Behavior**: Status badge color matches status code range (2xx Green, 3xx Blue, 4xx Amber, 5xx Rose).
- **Error Conditions**: Empty response body displays empty state container.

### FR-10: Request History Persistence
- **ID**: FR-10
- **Description**: The backend shall log all executed requests to SQLite database.
- **Input**: Request configuration and response execution metrics.
- **Processing**: Creates a record in `RequestHistory` table using `RequestHistory.objects.create(...)`.
- **Output**: Database record containing method, URL, headers, params, body, status code, response time, response size, and auto timestamp.
- **Expected Behavior**: Record immediately available for querying.
- **Error Conditions**: Database write failure is logged silently without crashing the proxy execution response.

### FR-11: History Search and Filtering
- **ID**: FR-11
- **Description**: The system shall allow users to search and filter request history.
- **Input**: Query string entered in `#history-search`.
- **Processing**: `filterHistory()` filters local history cache by matching URL, method, or status code substring.
- **Output**: Dynamically updated sidebar list.
- **Expected Behavior**: Case-insensitive filtering in real-time.
- **Error Conditions**: No matches show empty state message `"No matching requests found"`.

### FR-12: History Restoration
- **ID**: FR-12
- **Description**: The system shall allow restoring past request configurations into the active workspace.
- **Input**: Click event on a history sidebar item.
- **Processing**: `loadHistoryItem()` extracts method, URL, headers, and body from history item, updates DOM input fields, and triggers `updateParamsFromUrl()`.
- **Output**: Workspace inputs populated with historical request state.
- **Expected Behavior**: User can instantly re-execute past request.
- **Error Conditions**: None.

### FR-13: History Deletion
- **ID**: FR-13
- **Description**: The system shall support clearing stored request history.
- **Input**: User clicks "Clear" button in history sidebar header.
- **Processing**: Sends `DELETE` request to `/api/history/`. Backend executes `RequestHistory.objects.all().delete()`.
- **Output**: Empty history sidebar and reset database table.
- **Expected Behavior**: All history records removed from DB.
- **Error Conditions**: Failed delete request shows toast `"Failed to clear history"`.

### FR-14: API Presets
- **ID**: FR-14
- **Description**: The system shall provide quick template presets for instant API testing.
- **Input**: Selection from `#quick-presets` dropdown.
- **Processing**: `loadPreset()` populates predefined method, URL, headers, and body templates (e.g. JSONPlaceholder GET/POST/PUT/DELETE, HttpBin headers/delay).
- **Output**: Loaded preset into workspace fields.
- **Expected Behavior**: User can test working public APIs in 1 click.
- **Error Conditions**: Invalid preset key ignored.

### FR-15: Keyboard Shortcuts
- **ID**: FR-15
- **Description**: The system shall support dispatching requests via keyboard shortcuts.
- **Input**: User presses `Ctrl + Enter` (Windows/Linux) or `Cmd + Enter` (macOS).
- **Processing**: Global keydown event listener traps event, prevents browser default newline, and invokes `executeRequest()`.
- **Output**: Request execution trigger.
- **Expected Behavior**: Fast workflow execution without using mouse.
- **Error Conditions**: None.

---

## 4. Non-Functional Requirements (NFRs)

### NFR-01: Performance Requirements
- **Proxy Latency Overhead**: System processing overhead in `execute_request` view shall not exceed **15ms** per request.
- **Database Query Latency**: Fetching 50 recent history items (`GET /api/history/`) shall complete within **5ms**.

### NFR-02: Security Requirements
- **Server Safety**: Proxy request execution is restricted to HTTP/HTTPS schemes.
- **Host Binding**: Development server defaults to binding on local host interface.

### NFR-03: Reliability & Availability
- **System Timeout**: Outbound proxy requests strictly enforce a **15-second** connection/read timeout.
- **Graceful Failure**: Unreachable servers return structured 502/504 error payloads rather than uncaught Python stack traces.

### NFR-04: Usability & Accessibility
- **Responsive Theme**: Dark-themed UI (`#0b0f17` background) optimized for prolonged software development sessions.
- **Clipboard Integration**: One-click copying of response bodies using standard Web Clipboard API.

### NFR-05: Maintainability & Code Quality
- **Clean Architecture**: Decoupled view helpers (`_normalize_key_values`) and explicit ORM models (`RequestHistory`).
- **Testability**: Automated test suite with mock support (`@patch('client.views.requests.request')`).
