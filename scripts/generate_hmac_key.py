#!/usr/bin/env python3
"""Generate a cryptographically secure HMAC key for AIP Integrity Guardian.

Usage:
    python scripts/generate_hmac_key.py
    python scripts/generate_hmac_key.py --output /etc/guardian/hmac.key
"""

from __future__ import annotations

import argparse
import os
import secrets
import stat
import sys
from pathlib import Path


KEY_LENGTH = 32  # 256 bits


def generate_key(output_path: str) -> None:
    """Generate a 32-byte random key and write it to *output_path*.

    Sets file permissions to 0o600 (owner read/write only).
    Prints the hex representation for use in .env files.
    """
    key_bytes = secrets.token_bytes(KEY_LENGTH)

    # Ensure parent directory exists.
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    # Write raw key bytes.
    target.write_bytes(key_bytes)

    # Set restrictive permissions (best-effort on Windows).
    try:
        os.chmod(output_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

    hex_repr = key_bytes.hex()

    print(f"HMAC key generated successfully!")
    print(f"")
    print(f"  File:   {target.resolve()}")
    print(f"  Size:   {KEY_LENGTH} bytes ({KEY_LENGTH * 8} bits)")
    print(f"  Hex:    {hex_repr}")
    print(f"")
    print(f"To use in a .env file, set:")
    print(f"  GUARDIAN_HMAC_KEY={hex_repr}")
    print(f"")
    print(f"Or reference the key file:")
    print(f"  GUARDIAN_HMAC_KEY_FILE={target.resolve()}")
    print(f"")
    print(f"IMPORTANT: Keep this key secret. If lost, HMAC verification will")
    print(f"fail for all previously signed manifests.")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate a cryptographically secure HMAC key for AIP Integrity Guardian.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./secrets/hmac.key",
        help="Output file path for the key (default: ./secrets/hmac.key)",
    )
    args = parser.parse_args()

    # Safety check: do not overwrite an existing key without confirmation.
    if Path(args.output).exists():
        print(f"WARNING: Key file already exists at {args.output}")
        answer = input("Overwrite? (yes/no): ").strip().lower()
        if answer != "yes":
            print("Aborted.")
            sys.exit(0)

    generate_key(args.output)


if __name__ == "__main__":
    main()
