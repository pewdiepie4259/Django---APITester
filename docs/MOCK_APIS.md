# API Mock Server Guide

## 1. Concept
APIHub Mock Server enables developers to construct simulated HTTP endpoints with custom status codes, response headers, response bodies, and optional latency delays. Mock endpoints serve as stubs for frontend development and offline API testing.

## 2. Public Mock Routing
Each `MockEndpoint` generates an unpredictable `mock_key` (UUID4).
- **Endpoint URL**: `http://<domain>/api/mock/<mock_key>/`
- **Method Routing**: Supports `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `HEAD`, or `ALL`.
- **Public Access**: Does not require user authentication tokens to consume, enabling frontends and external webhooks to mock responses seamlessly.

## 3. Configurable Features
- **Response Status**: Any standard HTTP status code (200, 201, 400, 404, 500, etc.).
- **Headers**: Custom key-value pairs (e.g., `Content-Type: application/json`, `X-Custom-Header: value`).
- **Response Body**: Raw text or JSON payloads.
- **Latency Delay**: Simulated response delay up to 3000ms (3 seconds).

## 4. Mock Server Security Rules
- **No Code Execution**: Mock endpoints strictly return inert text/JSON payloads; arbitrary code execution or template rendering is prohibited.
- **Delay Bounding**: Latencies are capped at 3000ms to prevent worker thread starvation.
- **User Ownership**: Only the authenticated creator can edit or delete a mock endpoint configuration.
