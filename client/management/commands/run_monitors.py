from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from client.models import Monitor
from client.views import _execute_monitor


class Command(BaseCommand):
    help = "Executes scheduled server-side API monitor checks."

    def handle(self, *args, **options):
        now = timezone.now()
        monitors = Monitor.objects.filter(enabled=True)
        executed_count = 0

        for monitor in monitors:
            should_run = False
            if not monitor.last_run_at:
                should_run = True
            else:
                elapsed_minutes = (now - monitor.last_run_at).total_seconds() / 60.0
                if elapsed_minutes >= monitor.interval_minutes:
                    should_run = True

            if should_run:
                self.stdout.write(f"Executing Monitor #{monitor.id}: '{monitor.name}' ({monitor.method} {monitor.url})...")
                try:
                    _execute_monitor(monitor)
                    executed_count += 1
                except Exception as e:
                    self.stderr.write(f"Error executing Monitor #{monitor.id}: {str(e)}")

        self.stdout.write(self.style.SUCCESS(f"Successfully executed {executed_count} monitor checks."))
