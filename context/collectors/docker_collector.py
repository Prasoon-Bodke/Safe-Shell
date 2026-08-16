import subprocess


def collect_docker_info():
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return {
                "docker_available": False,
                "containers": []
            }

        containers = result.stdout.strip().splitlines()

        return {
            "docker_available": True,
            "containers": containers
        }

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {
            "docker_available": False,
            "containers": []
        }


if __name__ == "__main__":
    info = collect_docker_info()

    print("Docker Information:")
    print("Docker Available:", info["docker_available"])
    print("Running Containers:")

    for container in info["containers"]:
        print(" -", container)
