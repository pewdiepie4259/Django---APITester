from django.contrib import admin
from .models import RequestHistory


@admin.register(RequestHistory)
class RequestHistoryAdmin(admin.ModelAdmin):
    list_display = ('method', 'url', 'status_code', 'response_time_ms', 'response_size_kb', 'timestamp')
    list_filter = ('method', 'status_code', 'timestamp')
    search_fields = ('url', 'body')
    readonly_fields = ('timestamp',)
