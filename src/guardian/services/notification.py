"""Notification Service — email and webhook alerts.

Sends notifications to administrators when integrity events occur:
corruption detected, repair succeeded/failed, all replicas corrupted, etc.
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

import httpx

logger = logging.getLogger(__name__)


class NotificationService:
    """Dispatch integrity-event notifications via e-mail and webhook."""

    def __init__(self, settings: object) -> None:
        """Initialise with application settings.

        Parameters
        ----------
        settings:
            A :class:`guardian.config.Settings` instance (or compatible
            duck-typed object) exposing SMTP and webhook configuration.
        """
        self._admin_email: str = getattr(settings, "guardian_admin_email", "")
        self._smtp_host: str = getattr(settings, "guardian_smtp_host", "localhost")
        self._smtp_port: int = int(getattr(settings, "guardian_smtp_port", 587))
        self._smtp_user: str = getattr(settings, "guardian_smtp_user", "")
        self._smtp_password: str = getattr(settings, "guardian_smtp_password", "")
        self._webhook_url: str = getattr(settings, "guardian_webhook_url", "")

    # ------------------------------------------------------------------
    # Public high-level methods
    # ------------------------------------------------------------------

    def notify_corruption(self, aip_uuid: str, details: dict) -> bool:
        """Notify administrators that corruption has been detected.

        Parameters
        ----------
        aip_uuid:
            The UUID of the affected AIP.
        details:
            Dictionary with corruption specifics (files, hashes, etc.).

        Returns
        -------
        bool
            ``True`` if at least one notification channel succeeded.
        """
        subject = f"[AIP Guardian] CORRUPTION DETECTED — {aip_uuid}"
        body = (
            f"Corruption detected in AIP {aip_uuid}.\n\n"
            f"Details:\n{self._format_details(details)}"
        )
        return self._dispatch(subject, body, "corruption_detected", aip_uuid, details)

    def notify_repair_success(self, aip_uuid: str, details: dict) -> bool:
        """Notify that an auto-repair completed successfully."""
        subject = f"[AIP Guardian] Repair SUCCESS — {aip_uuid}"
        body = (
            f"AIP {aip_uuid} has been successfully repaired.\n\n"
            f"Details:\n{self._format_details(details)}"
        )
        return self._dispatch(subject, body, "repair_success", aip_uuid, details)

    def notify_repair_failure(self, aip_uuid: str, details: dict) -> bool:
        """Notify that an auto-repair attempt failed."""
        subject = f"[AIP Guardian] Repair FAILED — {aip_uuid}"
        body = (
            f"Auto-repair for AIP {aip_uuid} FAILED.\n\n"
            f"Manual intervention is required.\n\n"
            f"Details:\n{self._format_details(details)}"
        )
        return self._dispatch(subject, body, "repair_failure", aip_uuid, details)

    def notify_all_replicas_corrupted(self, aip_uuid: str) -> bool:
        """Notify that ALL replicas of an AIP are corrupted (critical).

        This is the worst-case scenario — no healthy source exists for
        automatic repair.
        """
        subject = f"[AIP Guardian] CRITICAL — ALL REPLICAS CORRUPTED — {aip_uuid}"
        body = (
            f"CRITICAL: All known replicas of AIP {aip_uuid} are corrupted.\n\n"
            f"No healthy replica could be found for automatic repair.\n"
            f"IMMEDIATE manual intervention is required.\n"
        )
        details = {"event": "all_replicas_corrupted", "aip_uuid": aip_uuid}
        return self._dispatch(subject, body, "all_replicas_corrupted", aip_uuid, details)

    # ------------------------------------------------------------------
    # Internal dispatch
    # ------------------------------------------------------------------

    def _dispatch(
        self,
        subject: str,
        body: str,
        event_type: str,
        aip_uuid: str,
        details: dict,
    ) -> bool:
        """Send via all configured channels; return ``True`` if any succeeded."""
        email_ok = self._send_email(subject, body)
        webhook_ok = self._send_webhook(
            {
                "event": event_type,
                "aip_uuid": str(aip_uuid),
                "subject": subject,
                "details": details,
            }
        )
        success = email_ok or webhook_ok

        if not success:
            logger.error(
                "All notification channels failed for event '%s' on AIP %s.",
                event_type,
                aip_uuid,
            )
        return success

    # ------------------------------------------------------------------
    # E-mail
    # ------------------------------------------------------------------

    def _send_email(self, subject: str, body: str) -> bool:
        """Send a plain-text e-mail via SMTP.

        Returns ``True`` on success, ``False`` on any failure.
        """
        if not self._admin_email:
            logger.debug("No admin e-mail configured; skipping e-mail notification.")
            return False

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self._smtp_user or "guardian@localhost"
        msg["To"] = self._admin_email
        msg.set_content(body)

        try:
            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=30) as smtp:
                smtp.ehlo()
                # Use STARTTLS when credentials are configured.
                if self._smtp_user and self._smtp_password:
                    smtp.starttls()
                    smtp.login(self._smtp_user, self._smtp_password)
                smtp.send_message(msg)
            logger.info("E-mail sent to %s: %s", self._admin_email, subject)
            return True
        except smtplib.SMTPException:
            logger.exception("Failed to send e-mail to %s", self._admin_email)
            return False
        except OSError:
            logger.exception("Network error sending e-mail to %s", self._admin_email)
            return False

    # ------------------------------------------------------------------
    # Webhook
    # ------------------------------------------------------------------

    def _send_webhook(self, payload: dict) -> bool:
        """POST a JSON payload to the configured webhook URL.

        Uses :mod:`httpx` with a 15-second timeout.

        Returns ``True`` on a 2xx response, ``False`` otherwise.
        """
        if not self._webhook_url:
            logger.debug("No webhook URL configured; skipping webhook notification.")
            return False

        try:
            with httpx.Client(timeout=15.0) as client:
                response = client.post(
                    self._webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
            if response.is_success:
                logger.info("Webhook delivered to %s (HTTP %d)", self._webhook_url, response.status_code)
                return True
            else:
                logger.warning(
                    "Webhook returned HTTP %d from %s",
                    response.status_code,
                    self._webhook_url,
                )
                return False
        except httpx.HTTPError:
            logger.exception("Webhook delivery failed for %s", self._webhook_url)
            return False

    # ------------------------------------------------------------------
    # Formatting helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_details(details: dict) -> str:
        """Pretty-format a details dict for inclusion in e-mail bodies."""
        lines: list[str] = []
        for key, value in details.items():
            if isinstance(value, list):
                lines.append(f"  {key}:")
                for item in value:
                    lines.append(f"    - {item}")
            else:
                lines.append(f"  {key}: {value}")
        return "\n".join(lines) if lines else "  (no details)"
