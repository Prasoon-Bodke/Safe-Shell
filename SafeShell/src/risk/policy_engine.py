# Policy Engine
# Member 5 - AI-Based Safe Linux Command Execution
from ai_result import get_ai_risk_result

LOW_RISK_COMMANDS = [
    "ls",
    "pwd",
    "whoami",
    "date",
    "echo"
]

HIGH_RISK_COMMANDS = [
    "rm",
    "chmod",
    "chown",
    "shutdown",
    "reboot",
    "mkfs",
    "dd"
]

DANGEROUS_PATTERNS = [
    "rm -rf",
    "rm -r",
    "chmod 777",
    ">/dev/",
    "mkfs.",
    "dd if="
]


def check_policy(command, risk_level="strict"):
    """Check command using rules and AI risk result."""

    command = command.strip()

    if not command:
        return False, "Empty command blocked"

    command_lower = command.lower()

    # Check dangerous patterns first
    for pattern in DANGEROUS_PATTERNS:
        if pattern in command_lower:
            return False, f"DANGEROUS PATTERN: {pattern} blocked"

    # Get AI risk result
    ai_result = get_ai_risk_result(command)

    ai_risk = ai_result["risk"]
    ai_score = ai_result["score"]
    ai_intent = ai_result["intent"]

    # High AI risk is always blocked
    if ai_risk == "HIGH":
        return False, (
            f"AI HIGH RISK: {ai_intent} "
            f"(score={ai_score}) blocked"
        )

    # Low-risk commands are allowed
    if command_lower.split()[0] in LOW_RISK_COMMANDS:
        return True, (
            f"AI LOW RISK: {ai_intent} "
            f"(score={ai_score}) allowed"
        )

    # Medium AI risk requires approval for developers
    if ai_risk == "MEDIUM" and risk_level == "moderate":
        return False, (
            f"AI MEDIUM RISK: {ai_intent} "
            f"(score={ai_score}) requires approval"
        )

    # Strict users block medium/unknown commands
    return False, (
        f"AI {ai_risk} RISK: {ai_intent} "
        f"(score={ai_score}) blocked"
    )


if __name__ == "__main__":
    command = input("Enter command: ")
    risk_level = input("Enter risk level (strict/moderate/high): ")

    allowed, message = check_policy(command, risk_level)

    print(message)