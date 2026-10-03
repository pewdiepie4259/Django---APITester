# API Contract Testing Guide

## 1. Concept
API Contract Testing in APIHub validates that real API HTTP responses strictly adhere to predefined schema contracts (derived from OpenAPI specifications or custom user constraints).

## 2. Contract Schema Definition
Each `SavedRequest` can store a JSON `contract_schema` containing:
- `expected_status`: Expected HTTP status code (e.g. `200`, `201`).
- `expected_content_type`: Expected MIME type substring (e.g. `application/json`).
- `required_fields`: List of required top-level JSON fields (e.g. `["id", "name", "email"]`).
- `field_types`: Dictionary mapping field names to expected scalar/composite types (`"integer"`, `"number"`, `"string"`, `"boolean"`, `"array"`, `"object"`).

## 3. Contract Evaluation Logic
When a request is executed (manually, via Collection Runner, or inside a Test Suite), `_validate_api_contract(contract_schema, response)` evaluates:
1. **Status Code**: Checks `response.status_code == expected_status`.
2. **Content Type**: Checks `expected_content_type in response.headers['Content-Type']`.
3. **Required Fields**: Asserts presence of every key specified in `required_fields`.
4. **Field Data Types**: Asserts python type compatibility:
   - `integer`: `isinstance(val, int) and not isinstance(val, bool)`
   - `number`: `isinstance(val, (int, float)) and not isinstance(val, bool)`
   - `string`: `isinstance(val, str)`
   - `boolean`: `isinstance(val, bool)`
   - `array`: `isinstance(val, list)`
   - `object`: `isinstance(val, dict)`

## 4. Contract Violation Reporting
Contract failures present clear, actionable messages:
- `✕ Contract Violation: Expected status 200, received 500`
- `✕ Contract Violation: Required field 'email' missing in response`
- `✕ Contract Violation: Field 'id' expected integer, received string ("123")`
