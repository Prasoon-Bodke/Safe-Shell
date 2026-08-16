# AI Risk Result Interface
# Member 5 - AI-Based Safe Linux Command Execution


def get_ai_risk_result(command):
    """
    Temporary AI interface.

    Later, this function will receive the
    actual result from the team's AI intent engine.
    """

    command_lower = command.lower()

    if "rm -rf" in command_lower:
        return {
            "risk": "HIGH",
            "score": 0.99,
            "intent": "destructive"
        }

    if command_lower.startswith("sudo"):
        return {
            "risk": "HIGH",
            "score": 0.95,
            "intent": "privileged"
        }

    if command_lower in ["ls", "pwd", "whoami", "date"]:
        return {
            "risk": "LOW",
            "score": 0.05,
            "intent": "information"
        }

    return {
        "risk": "MEDIUM",
        "score": 0.50,
        "intent": "unknown"
    }


if __name__ == "__main__":
    command = input("Enter command: ")

    result = get_ai_risk_result(command)

    print("AI Risk:", result["risk"])
    print("AI Score:", result["score"])
    print("AI Intent:", result["intent"])