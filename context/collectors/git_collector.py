import subprocess
import os


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def collect_git_info():
    print("Git Information:")

    is_repo = run_command(
        ["git", "rev-parse", "--is-inside-work-tree"]
    )

    if is_repo != "true":
        print("Is Git Repository: False")
        print("Branch: None")
        print("Status: None")
        return

    branch = run_command(
        ["git", "branch", "--show-current"]
    )

    status = run_command(
        ["git", "status", "--short"]
    )

    print("Is Git Repository: True")
    print("Branch:", branch if branch else "Detached/Unknown")
    print("Status:")
    print(status if status else "Clean")


if __name__ == "__main__":
    collect_git_info()
