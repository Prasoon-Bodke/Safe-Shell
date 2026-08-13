"""
knowledge_base.py

Loads the linux_kb.json knowledge base and exposes a lookup function
for retrieving command metadata by name.
"""

import json
import os
from typing import Optional


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_KB_FILENAME = "linux_kb.json"
_KB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), _KB_FILENAME)

# ---------------------------------------------------------------------------
# Internal loader
# ---------------------------------------------------------------------------

def _load_kb(path: str = _KB_PATH) -> dict:
    """Load the JSON knowledge base and index it by command name.

    Returns a dict mapping command name (str) -> full entry (dict).
    Raises FileNotFoundError or json.JSONDecodeError on bad input.
    """
    with open(path, "r", encoding="utf-8") as fh:
        entries = json.load(fh)

    kb_index: dict[str, dict] = {}
    for entry in entries:
        cmd = entry.get("command")
        if cmd:
            kb_index[cmd] = entry
    return kb_index


# Eagerly load once on import so every call to lookup() is O(1).
_KB: dict[str, dict] = _load_kb()

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup(command: str) -> Optional[dict]:
    """Return the knowledge-base entry for *command*, or ``None`` if unknown.

    Parameters
    ----------
    command : str
        The base command name to look up (e.g. ``"rm"``, ``"systemctl"``).

    Returns
    -------
    dict or None
        A dictionary with keys ``command``, ``flags``, ``category``,
        ``known_risk``, and optionally ``protected_paths``.
        Returns ``None`` when the command is not in the knowledge base.
    """
    # Normalise: strip leading path, whitespace, and take the basename
    # so that "/usr/bin/rm" and "  rm  " both resolve correctly.
    base = os.path.basename(command.strip())
    return _KB.get(base)


def all_commands() -> list[str]:
    """Return a sorted list of every command name in the knowledge base."""
    return sorted(_KB.keys())


def reload(path: str | None = None) -> None:
    """Re-read the knowledge base from disk (useful after editing the JSON).

    Parameters
    ----------
    path : str or None
        Optional override path; defaults to the module-level ``_KB_PATH``.
    """
    global _KB
    _KB = _load_kb(path or _KB_PATH)


# ---------------------------------------------------------------------------
# Quick self-test when run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"Loaded {len(_KB)} commands: {', '.join(all_commands())}\n")

    # Demo lookup
    for cmd in ("rm", "dd", "curl", "git", "systemctl", "nonexistent"):
        entry = lookup(cmd)
        if entry:
            risk = entry["known_risk"]
            n_flags = len(entry["flags"])
            max_danger = max(f["danger_weight"] for f in entry["flags"])
            print(f"  {cmd:12s}  risk={risk:<8s}  flags={n_flags}  max_danger={max_danger}")
        else:
            print(f"  {cmd:12s}  (not found)")
