from django.db import models
from django.contrib.auth.models import User
import uuid


class UserSettings(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='settings')
    theme = models.CharField(max_length=20, default='dark', choices=[('dark', 'Dark'), ('light', 'Light'), ('system', 'System')])
    compact_mode = models.BooleanField(default=False)
    request_timeout = models.IntegerField(default=15)
    updated_at = models.DateTimeField(auto_now=True)

    def to_dict(self):
        return {
            'theme': self.theme,
            'compact_mode': self.compact_mode,
            'request_timeout': self.request_timeout,
        }


class Collection(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='collections', null=True, blank=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default='')
    tags = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']
        indexes = [
            models.Index(fields=['user', 'name']),
            models.Index(fields=['user', '-updated_at']),
        ]

    def __str__(self):
        return self.name

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'tags': self.tags,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'saved_requests': [req.to_dict() for req in self.requests.all()],
            'versions': [v.to_dict() for v in self.api_versions.all()],
        }


class SavedRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='saved_requests', null=True, blank=True)
    collection = models.ForeignKey(Collection, on_delete=models.CASCADE, related_name='requests', null=True, blank=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default='')
    tags = models.JSONField(default=list, blank=True)
    method = models.CharField(max_length=10, default='GET')
    url = models.TextField(blank=True, default='')
    headers = models.JSONField(default=list, blank=True)
    params = models.JSONField(default=list, blank=True)
    auth_type = models.CharField(max_length=20, default='none')
    auth_data = models.JSONField(default=dict, blank=True)
    body = models.TextField(blank=True, default='')
    tests = models.JSONField(default=list, blank=True)
    contract_schema = models.JSONField(default=dict, blank=True) # OpenAPI schema validation
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['updated_at']
        indexes = [
            models.Index(fields=['user', 'collection']),
            models.Index(fields=['user', '-updated_at']),
        ]

    def __str__(self):
        return f"{self.name} ({self.method} {self.url})"

    def to_dict(self):
        return {
            'id': self.id,
            'collection_id': self.collection_id,
            'collection_name': self.collection.name if self.collection else None,
            'name': self.name,
            'description': self.description,
            'tags': self.tags,
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'params': self.params,
            'auth_type': self.auth_type,
            'auth_data': self.auth_data,
            'body': self.body,
            'tests': self.tests,
            'contract_schema': self.contract_schema,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }


class ApiTest(models.Model):
    saved_request = models.ForeignKey(SavedRequest, on_delete=models.CASCADE, related_name='test_definitions', null=True, blank=True)
    name = models.CharField(max_length=255)
    assertion_type = models.CharField(max_length=50)
    target_path = models.CharField(max_length=255, blank=True, default='')
    operator = models.CharField(max_length=20, default='equals')
    expected_value = models.TextField(blank=True, default='')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'assertion_type': self.assertion_type,
            'target_path': self.target_path,
            'operator': self.operator,
            'expected_value': self.expected_value,
        }


class TestRun(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='test_runs', null=True, blank=True)
    collection = models.ForeignKey(Collection, on_delete=models.CASCADE, related_name='runs', null=True, blank=True)
    saved_request = models.ForeignKey(SavedRequest, on_delete=models.CASCADE, related_name='runs', null=True, blank=True)
    total_tests = models.IntegerField(default=0)
    passed_tests = models.IntegerField(default=0)
    failed_tests = models.IntegerField(default=0)
    duration_ms = models.FloatField(default=0.0)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def to_dict(self):
        return {
            'id': self.id,
            'collection_id': self.collection_id,
            'saved_request_id': self.saved_request_id,
            'total_tests': self.total_tests,
            'passed_tests': self.passed_tests,
            'failed_tests': self.failed_tests,
            'duration_ms': round(self.duration_ms, 2),
            'timestamp': self.timestamp.isoformat(),
            'results': [r.to_dict() for r in self.results.all()]
        }


class TestResult(models.Model):
    test_run = models.ForeignKey(TestRun, on_delete=models.CASCADE, related_name='results')
    assertion_name = models.CharField(max_length=255)
    passed = models.BooleanField(default=True)
    expected = models.TextField(blank=True, default='')
    received = models.TextField(blank=True, default='')
    message = models.TextField(blank=True, default='')

    def to_dict(self):
        return {
            'id': self.id,
            'assertion_name': self.assertion_name,
            'passed': self.passed,
            'expected': self.expected,
            'received': self.received,
            'message': self.message,
        }


class Environment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='environments', null=True, blank=True)
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['user', 'name']),
        ]

    def __str__(self):
        return self.name

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'variables': [var.to_dict() for var in self.variables.all()],
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }


class EnvironmentVariable(models.Model):
    environment = models.ForeignKey(Environment, on_delete=models.CASCADE, related_name='variables')
    key = models.CharField(max_length=255)
    value = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['key']

    def __str__(self):
        return f"{self.key}={self.value}"

    def to_dict(self):
        return {
            'id': self.id,
            'environment_id': self.environment_id,
            'key': self.key,
            'value': self.value,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }


class RequestHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='request_history', null=True, blank=True)
    method = models.CharField(max_length=10)
    url = models.TextField()
    headers = models.JSONField(default=dict, blank=True)
    params = models.JSONField(default=dict, blank=True)
    body = models.TextField(blank=True, default='')
    status_code = models.IntegerField(null=True, blank=True)
    status_text = models.CharField(max_length=100, blank=True, default='')
    response_time_ms = models.FloatField(null=True, blank=True)
    response_size_kb = models.FloatField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['status_code']),
            models.Index(fields=['method']),
        ]

    def __str__(self):
        return f"{self.method} {self.url} ({self.status_code})"

    def to_dict(self):
        return {
            'id': self.id,
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'params': self.params,
            'body': self.body,
            'status_code': self.status_code,
            'status_text': self.status_text,
            'response_time_ms': round(self.response_time_ms, 2) if self.response_time_ms is not None else None,
            'response_size_kb': round(self.response_size_kb, 2) if self.response_size_kb is not None else None,
            'timestamp': self.timestamp.isoformat(),
        }


class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='audit_logs', null=True, blank=True)
    action = models.CharField(max_length=100)
    resource_type = models.CharField(max_length=50, blank=True, default='')
    resource_id = models.CharField(max_length=100, blank=True, default='')
    timestamp = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['action']),
        ]

    def __str__(self):
        username = self.user.username if self.user else 'Anonymous'
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {username} - {self.action} ({self.resource_type} {self.resource_id})"

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.user.username if self.user else 'Anonymous',
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata,
        }


# --- PHASE 5 ADVANCED API ENGINEERING MODELS ---

class ApiSpecification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='specifications')
    collection = models.ForeignKey(Collection, on_delete=models.SET_NULL, null=True, blank=True, related_name='specifications')
    title = models.CharField(max_length=255)
    version = models.CharField(max_length=50, default='1.0.0')
    description = models.TextField(blank=True, default='')
    servers = models.JSONField(default=list, blank=True)
    raw_spec = models.TextField(blank=True, default='')
    parsed_spec = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def to_dict(self):
        return {
            'id': self.id,
            'collection_id': self.collection_id,
            'title': self.title,
            'version': self.version,
            'description': self.description,
            'servers': self.servers,
            'parsed_spec': self.parsed_spec,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }


class ApiVersion(models.Model):
    STATUS_CHOICES = [
        ('DRAFT', 'Draft'),
        ('ACTIVE', 'Active'),
        ('DEPRECATED', 'Deprecated'),
        ('RETIRED', 'Retired'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_versions')
    collection = models.ForeignKey(Collection, on_delete=models.CASCADE, related_name='api_versions')
    version_name = models.CharField(max_length=50, default='v1.0')
    status = models.CharField(max_length=20, default='ACTIVE', choices=STATUS_CHOICES)
    changelog = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def to_dict(self):
        return {
            'id': self.id,
            'collection_id': self.collection_id,
            'version_name': self.version_name,
            'status': self.status,
            'changelog': self.changelog,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }


class TestSuite(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='test_suites')
    collection = models.ForeignKey(Collection, on_delete=models.SET_NULL, null=True, blank=True, related_name='test_suites')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default='')
    requests = models.JSONField(default=list, blank=True)  # List of saved request IDs
    stop_on_failure = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def to_dict(self):
        return {
            'id': self.id,
            'collection_id': self.collection_id,
            'name': self.name,
            'description': self.description,
            'requests': self.requests,
            'stop_on_failure': self.stop_on_failure,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }


class TestSuiteRun(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='suite_runs')
    suite = models.ForeignKey(TestSuite, on_delete=models.CASCADE, related_name='runs')
    total_tests = models.IntegerField(default=0)
    passed_tests = models.IntegerField(default=0)
    failed_tests = models.IntegerField(default=0)
    contract_passed = models.BooleanField(default=True)
    duration_ms = models.FloatField(default=0.0)
    details = models.JSONField(default=list, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def to_dict(self):
        return {
            'id': self.id,
            'suite_id': self.suite_id,
            'suite_name': self.suite.name,
            'total_tests': self.total_tests,
            'passed_tests': self.passed_tests,
            'failed_tests': self.failed_tests,
            'contract_passed': self.contract_passed,
            'duration_ms': round(self.duration_ms, 2),
            'timestamp': self.timestamp.isoformat(),
            'details': self.details,
        }


class Monitor(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='monitors')
    name = models.CharField(max_length=255)
    url = models.TextField(default='')
    method = models.CharField(max_length=10, default='GET')
    headers = models.JSONField(default=dict, blank=True)
    body = models.TextField(blank=True, default='')
    environment = models.ForeignKey(Environment, on_delete=models.SET_NULL, null=True, blank=True, related_name='monitors')
    interval_minutes = models.IntegerField(default=15)  # 5, 15, 30, 60, 1440
    expected_status = models.IntegerField(default=200)
    max_latency_ms = models.FloatField(default=2000.0)
    enabled = models.BooleanField(default=True)
    last_run_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return self.name

    def calculate_metrics(self):
        runs = list(self.runs.all()[:100])
        total = len(runs)
        if total == 0:
            return {
                'uptime_percent': 100.0,
                'avg_latency_ms': 0.0,
                'health_status': 'Unknown',
                'total_runs': 0,
            }
        healthy_count = sum(1 for r in runs if r.is_healthy)
        uptime = round((healthy_count / total) * 100.0, 1)

        latencies = [r.response_time_ms for r in runs if r.response_time_ms is not None]
        avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

        latest = runs[0]
        if not latest.is_healthy:
            health = 'Down'
        elif latest.response_time_ms and latest.response_time_ms > self.max_latency_ms:
            health = 'Degraded'
        else:
            health = 'Operational'

        return {
            'uptime_percent': uptime,
            'avg_latency_ms': avg_latency,
            'health_status': health,
            'total_runs': total,
        }

    def to_dict(self):
        metrics = self.calculate_metrics()
        return {
            'id': self.id,
            'name': self.name,
            'url': self.url,
            'method': self.method,
            'headers': self.headers,
            'body': self.body,
            'environment_id': self.environment_id,
            'environment_name': self.environment.name if self.environment else None,
            'interval_minutes': self.interval_minutes,
            'expected_status': self.expected_status,
            'max_latency_ms': self.max_latency_ms,
            'enabled': self.enabled,
            'last_run_at': self.last_run_at.isoformat() if self.last_run_at else None,
            'metrics': metrics,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }


class MonitorRun(models.Model):
    monitor = models.ForeignKey(Monitor, on_delete=models.CASCADE, related_name='runs')
    status_code = models.IntegerField(null=True, blank=True)
    response_time_ms = models.FloatField(null=True, blank=True)
    is_healthy = models.BooleanField(default=True)
    error_message = models.TextField(blank=True, default='')
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def to_dict(self):
        return {
            'id': self.id,
            'monitor_id': self.monitor_id,
            'status_code': self.status_code,
            'response_time_ms': round(self.response_time_ms, 2) if self.response_time_ms is not None else None,
            'is_healthy': self.is_healthy,
            'error_message': self.error_message,
            'timestamp': self.timestamp.isoformat(),
        }


class AlertRule(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='alert_rules')
    monitor = models.ForeignKey(Monitor, on_delete=models.CASCADE, related_name='alert_rules')
    condition = models.CharField(max_length=50, default='on_failure')  # on_failure, latency_exceeded, status_change
    threshold = models.FloatField(default=0.0)
    enabled = models.BooleanField(default=True)
    is_currently_failing = models.BooleanField(default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'monitor_id': self.monitor_id,
            'monitor_name': self.monitor.name,
            'condition': self.condition,
            'threshold': self.threshold,
            'enabled': self.enabled,
            'is_currently_failing': self.is_currently_failing,
        }


class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    monitor = models.ForeignKey(Monitor, on_delete=models.SET_NULL, null=True, blank=True, related_name='notifications')
    alert_type = models.CharField(max_length=50, default='MONITOR_DOWN')  # MONITOR_DOWN, MONITOR_RECOVERED, LATENCY_HIGH, CONTRACT_FAIL
    title = models.CharField(max_length=255)
    message = models.TextField(blank=True, default='')
    is_read = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def to_dict(self):
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'title': self.title,
            'message': self.message,
            'is_read': self.is_read,
            'timestamp': self.timestamp.isoformat(),
        }


class MockEndpoint(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mock_endpoints')
    name = models.CharField(max_length=255)
    mock_key = models.CharField(max_length=64, unique=True, default=uuid.uuid4)
    method = models.CharField(max_length=10, default='GET')
    path = models.CharField(max_length=255, default='/')
    response_status = models.IntegerField(default=200)
    response_headers = models.JSONField(default=dict, blank=True)
    response_body = models.TextField(blank=True, default='')
    delay_ms = models.IntegerField(default=0)  # Latency simulation (max 3000ms)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'mock_key': str(self.mock_key),
            'method': self.method,
            'path': self.path,
            'response_status': self.response_status,
            'response_headers': self.response_headers,
            'response_body': self.response_body,
            'delay_ms': self.delay_ms,
            'enabled': self.enabled,
            'mock_url': f"/api/mock/{self.mock_key}/",
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }


class PublicDocumentation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='public_docs')
    collection = models.ForeignKey(Collection, on_delete=models.CASCADE, related_name='public_docs')
    share_key = models.CharField(max_length=64, unique=True, default=uuid.uuid4)
    published = models.BooleanField(default=True)
    view_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def to_dict(self):
        return {
            'id': self.id,
            'collection_id': self.collection_id,
            'collection_name': self.collection.name,
            'share_key': str(self.share_key),
            'published': self.published,
            'view_count': self.view_count,
            'public_url': f"/docs/public/{self.share_key}/",
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }
