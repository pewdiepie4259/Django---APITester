# Machine Authentication & Personal Access Tokens Guide

## 1. Overview
APIHub provides Personal Access Tokens (PATs) and Service Account Tokens for machine-to-machine authentication (CLI tools, CI/CD runners, automated test scripts).

## 2. Token Security & Storage Architecture
- **Token Prefix**: Generated as `ahp_<hex_uuid>`.
- **Hashed Storage**: Plaintext tokens are **never** stored in the database. APIHub computes a SHA-256 hash (`hashlib.sha256`) and stores `token_hash`.
- **One-Time Display**: Plaintext tokens are displayed to the user **once** upon creation.
- **Revocation**: Tokens can be revoked instantly by owners or admins.

## 3. Scopes
- `collections:read` / `collections:write`: Access and modify API collections.
- `requests:read` / `requests:write`: Access and execute saved requests.
- `tests:run`: Trigger test suite executions.
- `workspace:read`: Query workspace details and metrics.

## 4. Header Format
```http
Authorization: Bearer ahp_a1b2c3d4e5f67890...
```
Or:
```http
X-APIHub-Token: ahp_a1b2c3d4e5f67890...
```
