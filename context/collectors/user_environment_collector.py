import os


def collect_user_environment():
    user_info = {
        "username": os.getenv("USER"),
        "home_directory": os.getenv("HOME"),
        "shell": os.getenv("SHELL"),
        "current_directory": os.getcwd()
    }

    return user_info


if __name__ == "__main__":
    info = collect_user_environment()

    print("User and Environment Information:")

    for key, value in info.items():
        print(f"{key}: {value}")
