from django.db import models


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
