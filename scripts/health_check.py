#!/usr/bin/env python3
"""Standalone health check for AIP Integrity Guardian.

Queries the /api/v1/health endpoint and exits with an appropriate
code.  Suitable for Docker HEALTHCHECK, monitoring tools (Nagios,
Prometheus Blackbox Exporter), or cron-based alerting.

Usage:
    python scripts/health_check.py
    python scripts/health_check.py --url http://guardian:8001
    python scripts/health_check.py --timeout 10

Exit codes:
    0 - Healthy or degraded
    1 - Unhealthy or unreachable
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


def check_health(base_url: str, timeout: int = 5) -> bool:
    """Query the Guardian health endpoint.

    Parameters
    ----------
    base_url:
        Base URL of the Guardian instance (e.g. ``http://localhost:8001``).
    timeout:
        Request timeout in seconds.

    Returns
    -------
    bool
        True if the service reports ``healthy`` or ``degraded``.
    """
    url = f"{base_url.rstrip('/')}/api/v1/health"

    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        status = data.get("status", "unknown")
        version = data.get("version", "unknown")
        db = data.get("database", False)
        redis = data.get("redis", False)
        celery = data.get("celery", False)
        archivematica = data.get("archivematica", False)

        print(f"Guardian Health Check")
        print(f"  Status:        {status}")
        print(f"  Version:       {version}")
        print(f"  Database:      {'OK' if db else 'FAIL'}")
        print(f"  Redis:         {'OK' if redis else 'FAIL'}")
        print(f"  Celery:        {'OK' if celery else 'FAIL'}")
        print(f"  Archivematica: {'OK' if archivematica else 'FAIL'}")

        return status in ("healthy", "degraded")

    except urllib.error.URLError as exc:
        print(f"ERROR: Could not reach Guardian at {url}: {exc}", file=sys.stderr)
        return False
    except json.JSONDecodeError:
        print(f"ERROR: Invalid JSON response from {url}", file=sys.stderr)
        return False
    except Exception as exc:
        print(f"ERROR: Unexpected error: {exc}", file=sys.stderr)
        return False


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Health check for AIP Integrity Guardian.",
    )
    parser.add_argument(
        "--url",
        type=str,
        default="http://localhost:8001",
        help="Base URL of the Guardian instance (default: http://localhost:8001)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Request timeout in seconds (default: 5)",
    )
    args = parser.parse_args()

    healthy = check_health(args.url, args.timeout)
    sys.exit(0 if healthy else 1)


if __name__ == "__main__":
    main()
