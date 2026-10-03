# Outbound Webhooks Guide

## 1. Overview
APIHub Webhooks send real-time HTTP POST notifications to external services (Slack, Discord, custom webhooks) upon key event triggers.

## 2. Event Types
- `monitor.failed`: Fired when an API Monitor health check fails.
- `monitor.recovered`: Fired when a failing API Monitor recovers to Operational status.
- `test.completed`: Fired when a Test Suite run completes.
- `ci.completed`: Fired when a CI/CD test execution finishes.

## 3. Webhook Security & HMAC Signatures
All webhook requests include an HMAC SHA256 signature in the `X-APIHub-Signature` header:

```http
X-APIHub-Signature: sha256=a1b2c3d4e5f6...
```

### Signature Verification Concept (Python Example):
```python
import hmac, hashlib

def verify_signature(secret, body_bytes, signature_header):
    expected_sig = "sha256=" + hmac.new(secret.encode('utf-8'), body_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, signature_header)
```

## 4. SSRF & Retry Policy
- **SSRF Shield**: Outbound webhook target URLs are validated using `_is_safe_url()` to block requests to private subnets or cloud metadata IPs.
- **Bounded Delivery**: Failed deliveries log error details in `WebhookDelivery` without crashing workspace execution.
