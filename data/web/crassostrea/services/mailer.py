"""Re-injects released quarantine mail into Postfix (listener without milter)."""
import smtplib

from flask import current_app


class ReleaseError(Exception):
    pass


def reinject(sender, rcpt, message):
    host = current_app.config["REINJECT_HOST"]
    port = current_app.config["REINJECT_PORT"]
    try:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.ehlo("crassostrea-web")
            refused = smtp.sendmail(sender or "", [rcpt], message)
    except (OSError, smtplib.SMTPException) as exc:
        raise ReleaseError(f"Postfix did not accept the message: {exc}") from exc
    if refused:
        raise ReleaseError(f"Postfix refused the recipient: {refused}")
