#!/usr/bin/env python3
"""Post-store hook for Archivematica automation-tools.

This standalone script is designed to be called by Archivematica
automation-tools after an AIP is stored.  It registers the AIP
with AIP Integrity Guardian via the REST API.

Dependencies: ``requests`` (stdlib + requests only; NO FastAPI/SQLAlchemy).

Usage (from automation-tools):
    python post_store_hook.py <aip_uuid> <aip_path>

Environment variables:
    GUARDIAN_URL     - Base URL of the Guardian API (default: http://localhost:8001)
    GUARDIAN_TOKEN   - Bearer token for authentication

Exit codes:
    0 - Success (AIP registered or already exists)
    1 - Failure (network error, auth error, etc.)
"""

from __future__ import annotations

import os
import sys

import requests


def register_aip(aip_uuid: str, aip_path: str) -> bool:
    """POST to Guardian to register the AIP.

    Parameters
    ----------
    aip_uuid:
        UUID of the AIP as assigned by Archivematica.
    aip_path:
        Filesystem path to the stored AIP package.

    Returns
    -------
    bool
        True on success, False on failure.
    """
    guardian_url = os.environ.get("GUARDIAN_URL", "http://localhost:8001").rstrip("/")
    guardian_token = os.environ.get("GUARDIAN_TOKEN", "")

    if not guardian_token:
        print("ERROR: GUARDIAN_TOKEN environment variable is not set.", file=sys.stderr)
        return False

    url = f"{guardian_url}/api/v1/aips/register"
    headers = {
        "Authorization": f"Bearer {guardian_token}",
        "Content-Type": "application/json",
    }
    payload = {
        "archivematica_uuid": aip_uuid,
        "storage_path": aip_path,
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)

        if response.status_code == 201:
            print(f"SUCCESS: AIP {aip_uuid} registered in Guardian.")
            return True
        elif response.status_code == 409:
            print(f"INFO: AIP {aip_uuid} already registered in Guardian.")
            return True
        else:
            print(
                f"ERROR: Guardian returned HTTP {response.status_code}: "
                f"{response.text}",
                file=sys.stderr,
            )
            return False

    except requests.ConnectionError:
        print(
            f"ERROR: Could not connect to Guardian at {guardian_url}",
            file=sys.stderr,
        )
        return False
    except requests.Timeout:
        print("ERROR: Request to Guardian timed out.", file=sys.stderr)
        return False
    except requests.RequestException as exc:
        print(f"ERROR: Request failed: {exc}", file=sys.stderr)
        return False


def main() -> None:
    """CLI entry point."""
    if len(sys.argv) != 3:
        print(
            f"Usage: {sys.argv[0]} <aip_uuid> <aip_path>",
            file=sys.stderr,
        )
        sys.exit(1)

    aip_uuid = sys.argv[1]
    aip_path = sys.argv[2]

    print(f"Registering AIP {aip_uuid} (path: {aip_path}) with Guardian...")

    success = register_aip(aip_uuid, aip_path)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
