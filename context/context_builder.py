import json
from datetime import datetime

from .collectors.docker_collector import collect_docker_info
from .collectors.filesystem_collector import collect_filesystem_info
from .collectors.git_collector import collect_git_info
from .collectors.network_collector import collect_network_info
from .collectors.package_collector import collect_package_info
from .collectors.process_collector import collect_process_info
from .collectors.system_collector import collect_system_info
from .collectors.user_environment_collector import collect_user_environment


def safe_collect(collector, name):
    try:
        return collector()
    except Exception as e:
        return {
            "status": "error",
            "collector": name,
            "error":str(e)
        }


def build_context():
    context = {
        "timestamp": datetime.now().isoformat(),
        "system": safe_collect(collect_system_info, "system"),
        "user_environment": safe_collect(
            collect_user_environment, "user_environment"
        ),
        "filesystem": safe_collect(
            collect_filesystem_info, "filesystem"
        ),
        "processes": safe_collect(
            collect_process_info, "processes"
        ),
        "packages": safe_collect(
            collect_package_info, "packages"
        ),
        "network": safe_collect(
            collect_network_info, "network"
        ),
        "git": safe_collect(
            collect_git_info, "git"
        ),
        "docker": safe_collect(
            collect_docker_info, "docker"
        )
    }

    return context


if __name__ == "__main__":
    context = build_context()
    print(json.dumps(context, indent=4, default=str))
