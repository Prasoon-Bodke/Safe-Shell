import os


def collect_filesystem_info():
    current_directory = os.getcwd()

    items = os.listdir(current_directory)

    files = []
    directories = []

    for item in items:
        full_path = os.path.join(current_directory, item)

        if os.path.isfile(full_path):
            files.append(item)

        elif os.path.isdir(full_path):
            directories.append(item)

    filesystem_info = {
        "current_directory": current_directory,
        "files": files,
        "directories": directories
    }

    return filesystem_info


if __name__ == "__main__":
    info = collect_filesystem_info()

    print("Filesystem Information:")
    print("Current Directory:", info["current_directory"])

    print("\nFiles:")
    for file in info["files"]:
        print(" -", file)

    print("\nDirectories:")
    for directory in info["directories"]:
        print(" -", directory)
