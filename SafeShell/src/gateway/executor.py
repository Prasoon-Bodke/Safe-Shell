import subprocess
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

sys.path.append(os.path.join(BASE_DIR, "policy"))
sys.path.append(os.path.join(BASE_DIR, "audit"))
sys.path.append(os.path.join(BASE_DIR, "personalization"))

from policy_engine import check_policy
from audit_logger import log_command
from user_profile import get_user_profile
from safety_checker import final_safety_check


def execute_command(command, role):
    # Get personalized user profile
    profile = get_user_profile(role)
    risk_level = profile["risk_level"]

    print(f"User: {profile['name']}")
    print(f"Policy: {risk_level}")

    # Check command against policy
    allowed, message = check_policy(command, risk_level)

    print(message)

    # Handle blocked or approval-required commands
    if not allowed:

        if "requires approval" in message.lower():
            approval = input("Do you approve this command? (yes/no): ")

            if approval.lower() != "yes":
                print("Command rejected by user.")

                log_command(
                    command,
                    role,
                    risk_level,
                    "REJECTED",
                    "User rejected approval request"
                )
                return

            print("Approval granted.")

            safe, safety_message = final_safety_check(command)

            print(safety_message)

            if not safe:
                log_command(
                    command,
                    role,
                    risk_level,
                    "BLOCKED",
                    safety_message
                )
                return

        else:
            log_command(
                command,
                role,
                risk_level,
                "BLOCKED",
                message
            )
            return

    # Execute allowed command
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )

        print(result.stdout)

        if result.stderr:
            print(result.stderr)

        log_command(
            command,
            role,
            risk_level,
            "ALLOWED",
            "Command executed successfully"
        )

    except Exception as e:
        print("Execution error:", e)

        log_command(
            command,
            role,
            risk_level,
            "ERROR",
            str(e)
        )


if __name__ == "__main__":
    role = input("Enter user role (normal/developer/admin): ")
    command = input("Enter command: ")

    execute_command(command, role)