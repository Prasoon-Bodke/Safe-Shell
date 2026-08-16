import subprocess


def collect_package_info():
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${binary:Package}\n"],
        capture_output=True,
        text=True
    )

    packages = []

    if result.returncode == 0:
        packages = result.stdout.strip().split("\n")

    return {
        "package_manager": "dpkg",
        "packages": packages
    }


if __name__ == "__main__":
    info = collect_package_info()

    print("Package Information:")
    print("Package Manager:", info["package_manager"])
    print("Number of Installed Packages:", len(info["packages"]))

    print("\nInstalled Packages:")

    for package in info["packages"]:
        print(" -", package)
