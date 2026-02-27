"""Tests for the HMAC manifest authenticator service (Component 2).

ISO 16363 section 4.3.3, section 5.2.2 — HMAC authentication for BagIt manifests.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import inspect
import os
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from guardian.services.hmac_authenticator import ManifestAuthenticator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _set_hmac_key(monkeypatch):
    """Set a deterministic HMAC key for all tests in this module."""
    monkeypatch.setenv("GUARDIAN_HMAC_KEY", "a" * 64)
    # Clear the settings cache so the new env var is picked up.
    from guardian.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def authenticator() -> ManifestAuthenticator:
    return ManifestAuthenticator()


@pytest.fixture
def aip_uuid() -> str:
    return str(uuid.uuid4())


# -------------------------------------------------------------------------
# 1. test_generate_hmac — deterministic HMAC generation
# -------------------------------------------------------------------------

class TestGenerateHMAC:
    def test_generate_hmac(
        self, authenticator: ManifestAuthenticator, valid_bag_path: Path
    ) -> None:
        """generate_hmac should produce a deterministic hex HMAC for a manifest file."""
        manifest = str(valid_bag_path / "manifest-sha256.txt")

        hmac1 = authenticator.generate_hmac(manifest)
        hmac2 = authenticator.generate_hmac(manifest)

        # Same file, same key -> identical HMAC.
        assert hmac1 == hmac2
        # Must be a 64-char hex string (SHA-256).
        assert len(hmac1) == 64
        assert all(c in "0123456789abcdef" for c in hmac1)


# -------------------------------------------------------------------------
# 2. test_verify_valid_hmac — correct HMAC returns True
# -------------------------------------------------------------------------

class TestVerifyValidHMAC:
    def test_verify_valid_hmac(
        self, authenticator: ManifestAuthenticator, valid_bag_path: Path
    ) -> None:
        """verify_hmac should return True when the stored HMAC matches."""
        manifest = str(valid_bag_path / "manifest-sha256.txt")
        correct_hmac = authenticator.generate_hmac(manifest)

        assert authenticator.verify_hmac(manifest, correct_hmac) is True


# -------------------------------------------------------------------------
# 3. test_verify_invalid_hmac — wrong HMAC returns False
# -------------------------------------------------------------------------

class TestVerifyInvalidHMAC:
    def test_verify_invalid_hmac(
        self, authenticator: ManifestAuthenticator, valid_bag_path: Path
    ) -> None:
        """verify_hmac should return False when the stored HMAC is wrong."""
        manifest = str(valid_bag_path / "manifest-sha256.txt")
        wrong_hmac = "0" * 64

        assert authenticator.verify_hmac(manifest, wrong_hmac) is False


# -------------------------------------------------------------------------
# 4. test_verify_tampered_manifest — modified file, original HMAC -> False
# -------------------------------------------------------------------------

class TestVerifyTamperedManifest:
    def test_verify_tampered_manifest(
        self,
        authenticator: ManifestAuthenticator,
        make_bag,
    ) -> None:
        """If the manifest file is modified after HMAC registration, the
        stored HMAC should no longer match."""
        bag_root = make_bag()
        manifest = str(bag_root / "manifest-sha256.txt")

        # Generate HMAC for the original manifest.
        original_hmac = authenticator.generate_hmac(manifest)

        # Tamper with the manifest.
        with open(manifest, "a", encoding="utf-8") as f:
            f.write("deadbeef00000000  data/injected_file.txt\n")

        # Verification should now fail.
        assert authenticator.verify_hmac(manifest, original_hmac) is False


# -------------------------------------------------------------------------
# 5. test_timing_safe — uses hmac.compare_digest
# -------------------------------------------------------------------------

class TestTimingSafe:
    def test_timing_safe(self) -> None:
        """Verify that ManifestAuthenticator uses hmac.compare_digest."""
        source = inspect.getsource(ManifestAuthenticator)
        assert "compare_digest" in source, (
            "ManifestAuthenticator must use hmac.compare_digest for timing-safe comparison"
        )


# -------------------------------------------------------------------------
# 6. test_register_all_manifests — registers 2-3 manifests in DB
# -------------------------------------------------------------------------

class TestRegisterAllManifests:
    def test_register_all_manifests(
        self,
        authenticator: ManifestAuthenticator,
        valid_bag_path: Path,
        aip_uuid: str,
    ) -> None:
        """register_aip should record HMACs for all existing manifest files."""
        from unittest.mock import MagicMock

        # Create a mock session that supports the required operations.
        mock_session = MagicMock()
        mock_execute = MagicMock()
        mock_execute.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_execute

        result = authenticator.register_aip(mock_session, aip_uuid, str(valid_bag_path))

        assert result["registered"] >= 1
        assert len(result["manifests"]) >= 1

        # Verify that session.add was called for each new HMAC record.
        assert mock_session.add.call_count >= 1

        # All HMAC values should be valid hex strings.
        for manifest_name, hmac_value in result["manifests"].items():
            assert len(hmac_value) == 64
            assert all(c in "0123456789abcdef" for c in hmac_value)


# -------------------------------------------------------------------------
# 7. test_different_keys — different keys produce different HMACs
# -------------------------------------------------------------------------

class TestDifferentKeys:
    def test_different_keys(self, valid_bag_path: Path, monkeypatch) -> None:
        """Two different HMAC keys should produce different HMAC values."""
        from guardian.config import get_settings

        manifest = str(valid_bag_path / "manifest-sha256.txt")

        # Key A
        monkeypatch.setenv("GUARDIAN_HMAC_KEY", "a" * 64)
        get_settings.cache_clear()
        auth_a = ManifestAuthenticator()
        hmac_a = auth_a.generate_hmac(manifest)

        # Key B
        monkeypatch.setenv("GUARDIAN_HMAC_KEY", "b" * 64)
        get_settings.cache_clear()
        auth_b = ManifestAuthenticator()
        hmac_b = auth_b.generate_hmac(manifest)

        assert hmac_a != hmac_b, (
            "Different keys must produce different HMAC values for the same file"
        )
