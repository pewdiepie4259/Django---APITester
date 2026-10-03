# API Versioning & Lifecycle Guide

## 1. Versioning Architecture
APIHub organizes Collections into explicit API versions (e.g. `v1.0`, `v2.0`). This allows development teams to manage lifecycle progression, communicate breaking changes, and track changelogs.

## 2. Version Lifecycle Statuses
Each `ApiVersion` object maintains a lifecycle status:
- `DRAFT`: In active design or preliminary development.
- `ACTIVE`: Current production-supported version.
- `DEPRECATED`: Supported but scheduled for sunsetting. Displays prominent warnings when requests are executed against endpoints in this version.
- `RETIRED`: Discontinued version.

## 3. Release Notes & Changelogs
API Versions maintain an explicit `changelog` field documenting release notes (added features, modified endpoints, removed fields).

## 4. Shareable Public Documentation
Collections and API Versions can be published to a public read-only link:
- **Shareable URL**: `/docs/public/<share_key>/`
- **Secret Redaction**: Automatically redacts sensitive header keys (`Authorization`, `X-Api-Key`, `Cookie`, `Secret`, `Token`, `Password`) with `[REDACTED]`.
- **Public View**: Clean, read-only interface without workspace controls or private user data.
