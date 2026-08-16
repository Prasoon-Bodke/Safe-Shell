import subprocess


def collect_process_info():
    result = subprocess.run(
        ["ps", "-eo", "pid,comm"],
        capture_output=True,
        text=True
    )

    processes = []

    lines = result.stdout.strip().split("\n")

    for line in lines[1:]:
        parts = line.strip().split(None, 1)

        if len(parts) == 2:
            pid, command = parts
            processes.append({
                "pid": pid,
                "command": command
            })

    return {
        "processes": processes
    }


if __name__ == "__main__":
    info = collect_process_info()

    print("Running Processes:")

    for process in info["processes"]:
        print(
            f"PID: {process['pid']} | "
            f"Command: {process['command']}"
        )
