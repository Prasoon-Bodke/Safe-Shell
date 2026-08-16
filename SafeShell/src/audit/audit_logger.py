# Audit Logger
# Member 5 - AI-Based Safe Linux Command Execution

from datetime import datetime
import os

LOG_FILE = os.path.join(os.path.dirname(__file__), "audit.log")


def log_command(command, role, risk_level, status, message):
    """Record every command decision in the audit log."""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a") as file:
        file.write(
            f"[{timestamp}] "
            f"USER_ROLE: {role} | "
            f"RISK: {risk_level} | "
            f"COMMAND: {command} | "
            f"STATUS: {status} | "
            f"REASON: {message}\n"
        )


if __name__ == "__main__":
    log_command(
        "test",
        "normal",
        "strict",
        "ALLOWED",
        "Test audit entry"
    )

    print("Audit log created.")