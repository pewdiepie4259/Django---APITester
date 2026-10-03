from django.db import models


class Collection(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return self.name

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'saved_requests': [req.to_dict() for req in self.requests.all()]
        }


class SavedRequest(models.Model):
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
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['updated_at']

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
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

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
