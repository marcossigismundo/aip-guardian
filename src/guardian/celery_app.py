"""Celery application configuration."""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from guardian.config import get_settings

settings = get_settings()

celery = Celery(
    "guardian",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
)

# Autodiscover tasks from the tasks package
celery.autodiscover_tasks(["guardian.tasks"])

# Celery Beat schedule — periodic tasks
celery.conf.beat_schedule = {
    # Weekly fixity verification — Sunday 02:00 UTC
    "weekly-fixity-check": {
        "task": "guardian.tasks.fixity_tasks.verify_all_aips",
        "schedule": crontab(hour=2, minute=0, day_of_week="sunday"),
    },
    # Daily health check — 06:00 UTC
    "daily-health-check": {
        "task": "guardian.tasks.fixity_tasks.pipeline_health_check",
        "schedule": crontab(hour=6, minute=0),
    },
    # Daily RFC 3161 anchor — 23:00 UTC
    "daily-anchor": {
        "task": "guardian.tasks.anchor_tasks.submit_daily_anchor",
        "schedule": crontab(hour=23, minute=0),
    },
    # Weekly audit chain verification — Monday 03:00 UTC
    "weekly-chain-verify": {
        "task": "guardian.tasks.audit_tasks.verify_audit_chain",
        "schedule": crontab(hour=3, minute=0, day_of_week="monday"),
    },
}
