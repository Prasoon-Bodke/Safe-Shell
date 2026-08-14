import subprocess


def collect_network_info():
    result = subprocess.run(
        ["ip", "addr"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        return {
            "network_information": result.stdout
        }

    return {
        "network_information": "Unable to collect network information"
    }


if __name__ == "__main__":
    info = collect_network_info()

    print("Network Information:")
    print(info["network_information"])
