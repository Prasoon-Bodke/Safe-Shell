import platform


def collect_system_info():
    system_info = {
        "os": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor()
    }

    return system_info


if __name__ == "__main__":
    info = collect_system_info()

    print("System Information:")
    for key, value in info.items():
        print(f"{key}: {value}")
