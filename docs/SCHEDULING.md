# Scheduled Checks & Background Job Architecture

## 1. Architecture Choice & Rationale
APIHub uses a lightweight, robust, server-side background job execution strategy implemented via custom Django management commands:
```bash
python manage.py run_monitors
```
### Why This Architecture Was Chosen
- **Zero Heavy Infrastructure**: Eliminates external dependencies on Redis, Celery, or RabbitMQ, keeping the Django architecture clean and easy to deploy on standard servers.
- **Server-Side Reliability**: Does not depend on active browser tabs or client-side JavaScript timers.
- **Cron / Systemd Compatibility**: Can be invoked periodically via standard Linux `cron` jobs, Windows Task Scheduler, or Docker sidecar containers.

## 2. Execution Flow
1. **Trigger**: `python manage.py run_monitors` is executed every minute (or via scheduler).
2. **Monitor Lookup**: Queries all enabled `Monitor` instances whose `last_run_at` + `interval_minutes` is overdue.
3. **Execution**: Dispatches `_execute_monitor(monitor)` for each overdue target.
4. **Validation**: Measures status code, latency, and assertions; logs `MonitorRun`.
5. **Alert Processing**: Evaluates `AlertRule` conditions and sends deduplicated notifications.
6. **Graceful Error Handling**: Individual monitor execution failures do not crash the management loop; errors are captured in `MonitorRun.error_message`.

## 3. Concurrency & Safety Controls
- **Locking**: Prevents duplicate executions of the same monitor within its active check interval.
- **SSRF Shield**: All scheduled check URLs are validated against `_is_safe_url()` before socket connections are initiated.
- **Strict Bounded Timeout**: Requests are constrained by a 15-second timeout.
