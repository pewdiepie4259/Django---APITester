# OpenAPI & Swagger Engineering Guide

## 1. Overview
APIHub supports full-lifecycle OpenAPI 3.x and Swagger 2.0 specifications. Users can import specification files (.yaml, .yml, .json) to automatically generate APIHub Collections, Saved Requests, Headers, Parameters, and Server Base URLs. Furthermore, Collections can be exported as standard OpenAPI 3.0 specs.

## 2. Supported Versions & Formats
- **OpenAPI 3.0.x / 3.1.x**: YAML and JSON formats.
- **Swagger 2.0**: JSON and YAML formats.
- **File Upload Limits**: Up to 10MB per specification file.

## 3. OpenAPI Import Pipeline
1. **Upload & Content Extraction**: Secure file upload or inline raw specification payload.
2. **Safe Parser**: Parses YAML using `yaml.safe_load()` and JSON via `json.loads()`. Unsafe tags or code execution attempts are strictly blocked.
3. **Structure Validation**: Verifies `openapi` / `swagger` root keys, `info.title`, `info.version`, and `paths` dictionary.
4. **Server & Base URL Extraction**: Reads the `servers` list. Selects the primary server URL (e.g. `https://api.example.com/v1`) as base URL for endpoints.
5. **Collection Generation**: Creates an isolated `Collection` and converts paths & operations into individual `SavedRequest` records.
6. **Authentication Schema Mapping**:
   - `apiKey` → Header or Query Param authentication
   - `bearer` → Bearer Token configuration
   - `basic` → HTTP Basic Auth configuration

## 4. OpenAPI Export Pipeline
APIHub Collections can be exported at any time into a valid OpenAPI 3.0 specification:
- **Formats**: JSON (default) or YAML (`?format=yaml`).
- **Generated Nodes**: `openapi`, `info`, `servers`, `paths`, `parameters`, `requestBody`, `responses`.
- **Integrity Guarantee**: Only explicitly stored information is exported (no placeholder or fake data).

## 5. Validation Error Handling
If an imported specification is invalid, APIHub returns a user-friendly error message detailing the specific issue (e.g., `Missing required root 'paths' element`) while concealing raw Python stack traces.
