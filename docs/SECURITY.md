# APIHub — Security Architecture & Hardening Specification

APIHub is an API client and testing platform. Because it dispatches outbound proxy requests on behalf of users, security is a paramount architectural requirement.

---

## 1. Authentication & Session Security

- **Django Auth Framework**: Built-in Django session authentication with hashed passwords (`PBKDF2PasswordHasher` with SHA256).
- **Password Strength Validation**: Enforced via Django's `AUTH_PASSWORD_VALIDATORS` (`MinimumLengthValidator`, `CommonPasswordValidator`, `NumericPasswordValidator`, `UserAttributeSimilarityValidator`).
- **Session Protection**:
  - `SESSION_COOKIE_HTTPONLY = True` (Prevents client-side script access to session cookies).
  - `SESSION_COOKIE_SECURE = True` in production (Enforces HTTPS transport).
  - `SESSION_COOKIE_SAMESITE = 'Lax'` (Protects against CSRF attacks).

---

## 2. Server-Side Request Forgery (SSRF) Protection

APIHub dispatches outbound HTTP proxy requests in `execute_request`. Strict server-side SSRF validation is enforced prior to dispatch:

### Blocked Hostnames & Addresses
- Loopback addresses (`127.0.0.1`, `localhost`, `::1`, `0.0.0.0`).
- Cloud Metadata Endpoints (`169.254.169.254`, `metadata.google.internal`, `instance-data`, `metadata`).
- Private RFC1918 IPv4 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- IPv6 link-local and multicast addresses (`fe80::/10`, `fc00::/7`).

### DNS Resolution Inspection
- Input hostnames are resolved server-side via `socket.gethostbyname()`.
- The resolved IP address is validated against `ipaddress.ip_address(ip).is_private` and `ip.is_loopback` before establishing socket connections.

---

## 3. Data Isolation & Authorization

- **Server-Side Scope Checks**: Every model (`Collection`, `SavedRequest`, `Environment`, `RequestHistory`, `TestRun`) contains a `user` ForeignKey.
- **Query Scoping**: Database queries filter by `user=request.user`.
- **Detail Access Guards**: Endpoints verify `object.user == request.user`. Unauthorized requests return HTTP `404 Not Found` or `401 Unauthorized` responses to avoid exposing object existence.

---

## 4. Secret Protection & Header Redaction

- **History Sanitize**: Sensitive headers (`Authorization`, `Bearer`, `X-API-Key`, `Cookie`, `Set-Cookie`, `Secret`, `Token`, `Password`) are automatically redacted prior to database storage in `RequestHistory`.
- **UI Masking**: Environment secret keys are masked in the UI with explicit show/hide controls.
- **Log Masking**: Passwords, tokens, and authorization headers are omitted from Django application logs.

---

## 5. Input Validation & Protection Limits

- **Request Size Protection**: Maximum inbound payload size limit enforced at `10MB` (`413 Payload Too Large`).
- **Response Display Limits**: Response viewer truncates body previews exceeding `2MB` to prevent browser thread freezing, providing a direct raw download button.
- **Request Timeout Policy**: Proxy requests enforce a default `15s` timeout limit (configurable up to `30s` max) to prevent server thread exhaustion.

---

## 6. Audit Logging

APIHub maintains a dedicated `AuditLog` table capturing security actions:
- User Logins & Logouts
- Password & Profile Updates
- Collection & Request Creation/Deletion
- Collection Runner Executions
- Data Exports & Account Deletions
