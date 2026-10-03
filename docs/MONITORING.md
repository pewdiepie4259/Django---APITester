# API Monitoring & Endpoint Health Guide

## 1. Overview
APIHub API Monitors allow users to schedule automated, periodic health checks against production endpoints to continuously measure availability, latency, status codes, and operational status.

## 2. Monitor Models & Data Architecture
- **`Monitor`**: Stores target URL, method, headers, expected status, max latency threshold (ms), check interval (minutes), and enabled flag.
- **`MonitorRun`**: Records individual check execution timestamps, status codes, response times, health results (`is_healthy`), and error details.
- **`AlertRule`**: Defines alert triggering conditions (`on_failure`, `on_latency_exceeded`) and tracks `is_currently_failing` state.
- **`Notification`**: Stores user notifications for `MONITOR_DOWN` and `MONITOR_RECOVERED` events.

## 3. Endpoint Health Rules
Endpoint status is derived dynamically from historical `MonitorRun` metrics:
- **Operational**: Recent check succeeded (`status_code == expected_status`) and response latency is within `max_latency_ms`.
- **Degraded**: Check succeeded with expected status code, but latency exceeded `max_latency_ms`.
- **Down**: Check failed with non-matching status code (e.g. 500), connection timeout, or SSRF security block.
- **Unknown**: Insufficient monitor run data.

## 4. Operational Uptime Calculation
Uptime percentage is computed strictly from empirical `MonitorRun` historical records:
$$\text{Uptime \%} = \left( \frac{\text{Total Healthy Runs}}{\text{Total Runs}} \right) \times 100$$
If zero runs exist, APIHub displays "Not enough data" instead of generating synthetic values.

## 5. Security & Protection Controls
Monitors strictly enforce:
- SSRF filtering via `_is_safe_url()` blocking loopback (`127.0.0.1`), RFC 1918 private IPs, and cloud metadata endpoints (`169.254.169.254`).
- Bounded 15-second request execution timeout.
- Data retention limits (stores latency, status, error message; does not persist response payloads).
