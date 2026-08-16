# Final Safety Checker
# Member 5 - AI-Based Safe Linux Command Execution

DANGEROUS_PATTERNS = [
    "rm -rf",
    "rm -r",
    "chmod 777",
    "shutdown",
    "reboot",
    "mkfs",
    "dd if=",
    ">/dev/"
]


def final_safety_check(command):
    """Perform a final safety check before execution."""

    command_lower = command.lower().strip()

    for pattern in DANGEROUS_PATTERNS:
        if pattern in command_lower:
            return False, f"FINAL SAFETY BLOCK: {pattern}"

    return True, "Final safety check passed"


if __name__ == "__main__":
    command = input("Enter command for final safety check: ")

    safe, message = final_safety_check(command)

    print(message)