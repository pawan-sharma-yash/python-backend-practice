"""
Simple SMTP email service. Defaults to Gmail (`smtp.gmail.com:587`) but fully
configurable via env vars in `app.core.config.Settings`:

  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM, SMTP_TLS, SMTP_TIMEOUT

For Gmail: use an App Password (not your normal password) with 2-Step Verification.
Set SMTP_USER and SMTP_PASSWORD env vars. SMTP_FROM defaults to SMTP_USER.

If SMTP_USER / SMTP_PASSWORD are not configured, sending is skipped and the
OTP is logged to stdout (useful for dev/test without real credentials).
"""

import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import settings

logger = logging.getLogger(__name__)


def _is_smtp_configured() -> bool:
    return bool(settings.smtp_user and settings.smtp_password)


def send_email(to_email: str, subject: str, body_text: str, body_html: str | None = None) -> bool:
    """Send an email via SMTP. Returns True on success, False otherwise.

    When SMTP is not configured, logs and returns True (dev mode) so the
    OTP flow still works without real email delivery.
    """
    if not _is_smtp_configured():
        logger.warning(
            "SMTP not configured (SMTP_USER/SMTP_PASSWORD missing) – "
            "skipping real email send. To: %s | Subject: %s | Body: %s",
            to_email,
            subject,
            body_text,
        )
        print(f"[DEV EMAIL] To: {to_email}\nSubject: {subject}\n{body_text}")
        return True

    msg = MIMEMultipart("alternative")
    msg["From"] = settings.smtp_from or settings.smtp_user
    msg["To"] = to_email
    msg["Subject"] = subject

    # Plain text part always
    msg.attach(MIMEText(body_text, "plain", "utf-8"))
    if body_html:
        msg.attach(MIMEText(body_html, "html", "utf-8"))

    try:
        if settings.smtp_tls:
            context = ssl.create_default_context()
            with smtplib.SMTP(
                settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout
            ) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(settings.smtp_user, settings.smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(
                settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout
            ) as server:
                if settings.smtp_user:
                    server.login(settings.smtp_user, settings.smtp_password)
                server.send_message(msg)
        logger.info("Email sent to %s via %s:%s", to_email, settings.smtp_host, settings.smtp_port)
        return True
    except Exception as exc:
        logger.exception("Failed to send email to %s: %s", to_email, exc)
        return False


def send_otp_email(to_email: str, otp: str) -> bool:
    """Convenience wrapper for OTP verification emails."""
    subject = f"Your {settings.app_name} verification code"
    minutes = settings.otp_expire_minutes
    body_text = (
        f"Your verification code is: {otp}\n\n"
        f"This code expires in {minutes} minutes.\n"
        f"If you didn't request this, please ignore this email.\n"
    )
    body_html = (
        f"<p>Your verification code is:</p>"
        f"<h2 style='letter-spacing: 4px;'>{otp}</h2>"
        f"<p>This code expires in <b>{minutes} minutes</b>.</p>"
        f"<p>If you didn't request this, please ignore this email.</p>"
    )
    return send_email(to_email, subject, body_text, body_html)
