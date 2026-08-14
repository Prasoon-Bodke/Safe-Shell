import json

from .context_builder import build_context


def save_context():
    context = build_context()

    with open("context.json", "w") as file:
        json.dump(context, file, indent=4, default=str)

    print("Context saved successfully to context.json")


if __name__ == "__main__":
    save_context()
