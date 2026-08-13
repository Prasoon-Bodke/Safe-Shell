"""
rules_engine.py

Deterministic rule-based risk evaluator for parsed shell commands.

Input
-----
- ast : dict  — Bashlex-style AST node with keys:
      command, flags, args, target_path, is_sudo, is_recursive, is_force,
      raw (optional full command string), pipe_to (optional downstream cmd)
- kb_entry : dict | None — knowledge_base.lookup() result for the command

Output
------
dict with keys:  risk  ('low'|'medium'|'high'|'critical'),
                 matched_rule (str),
                 reason (str)
"""

from __future__ import annotations

import os
import re
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SYSTEM_PATHS: set[str] = {
    "/", "/boot", "/bin", "/sbin", "/etc", "/usr", "/var",
    "/lib", "/lib64", "/dev", "/proc", "/sys", "/root", "/tmp",
}

HOME_ROOT_PATHS: set[str] = {"/home", "/root"}

CRITICAL_PATHS: set[str] = SYSTEM_PATHS | HOME_ROOT_PATHS

SENSITIVE_FILES: set[str] = {
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/gshadow",
    "/etc/master.passwd", "/proc/sysrq-trigger",
}

DEVICE_RE = re.compile(r"/dev/(sd[a-z]\d*|nvme\d+n\d+(p\d+)?|vd[a-z]\d*|xvd[a-z]\d*|mmcblk\d+(p\d+)?)")

FORK_BOMB_RE = re.compile(r":\(\)\s*\{[^}]*\|\s*:.*&\s*\}\s*;\s*:")

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _normalise_path(p: str) -> str:
    """Strip trailing slashes (except bare '/') and resolve '.' / '..'."""
    if not p:
        return ""
    p = p.rstrip("/") or "/"
    return os.path.normpath(p).replace("\\", "/")


def _extract_paths(ast: dict) -> list[str]:
    """Gather every path-like string from target_path and args."""
    paths: list[str] = []
    tp = ast.get("target_path")
    if tp:
        paths.append(_normalise_path(tp))
    for arg in ast.get("args", []):
        if "=" in arg:
            val = arg.split("=", 1)[1]
            if val.startswith("/"):
                paths.append(_normalise_path(val))
        elif arg.startswith("/"):
            paths.append(_normalise_path(arg))
    return paths


def _path_is_critical(p: str) -> bool:
    """Return True if *p* is or is an ancestor of a critical system path."""
    p = _normalise_path(p)
    if p in CRITICAL_PATHS:
        return True
    for cp in CRITICAL_PATHS:
        if cp.startswith(p + "/") or p == cp:
            return True
    return False


def _raw(ast: dict) -> str:
    """Return the raw command string, falling back to reconstructed form."""
    r = ast.get("raw", "")
    if r:
        return r
    parts = []
    if ast.get("is_sudo"):
        parts.append("sudo")
    if ast.get("command"):
        parts.append(ast["command"])
    parts.extend(ast.get("flags", []))
    parts.extend(ast.get("args", []))
    return " ".join(parts)


# ===================================================================== #
#                       RULE FUNCTIONS                                    #
# ===================================================================== #

def _rule_fork_bomb(ast: dict, kb_entry: Optional[dict]) -> Optional[dict]:
    """Detect fork-bomb syntax :(){ :|:& };:"""
    raw = _raw(ast)
    collapsed = re.sub(r"\s+", " ", raw)
    if FORK_BOMB_RE.search(collapsed) or FORK_BOMB_RE.search(raw):
        return {
            "risk": "critical",
            "matched_rule": "fork_bomb",
            "reason": "Fork bomb detected — will exhaust all system resources and crash the machine",
        }
    return None


def _rule_sudo_recursive_force_critical_path(ast: dict, kb_entry: Optional[dict]) -> Optional[dict]:
    """sudo + recursive + force targeting / or /home etc."""
    if not (ast.get("is_sudo") and ast.get("is_recursive") and ast.get("is_force")):
        return None
    paths = _extract_paths(ast)
    for p in paths:
        if _path_is_critical(p):
            return {
                "risk": "critical",
                "matched_rule": "sudo_recursive_force_critical_path",
                "reason": (
                    f"Privileged recursive forced operation on critical path '{p}' "
                    f"— can irreversibly destroy the system"
                ),
            }
    return None


def _rule_chmod_777_recursive_system(ast: dict, kb_entry: Optional[dict]) -> Optional[dict]:
    """chmod 777 -R on a system path."""
    if ast.get("command") != "chmod":
        return None
    all_tokens = ast.get("flags", []) + ast.get("args", [])
    has_777 = "777" in all_tokens
    is_recursive = ast.get("is_recursive") or "-R" in all_tokens or "--recursive" in all_tokens
    if not (has_777 and is_recursive):
        return None
    paths = _extract_paths(ast)
    for p in paths:
        if _path_is_critical(p):
            return {
                "risk": "critical",
                "matched_rule": "chmod_777_recursive_system",
                "reason": (
                    f"chmod 777 -R on system path '{p}' — makes all files world-readable, "
                    f"world-writable, and world-executable; destroys filesystem security"
                ),
            }
    return None


def _rule_dd_mkfs_device(ast: dict, kb_entry: Optional[dict]) -> Optional[dict]:
    """dd, mkfs, shred, wipefs, blkdiscard, parted targeting raw block devices."""
    cmd = ast.get("command", "")
    destructive_cmds = ("dd", "shred", "wipefs", "blkdiscard", "parted")
    is_destructive = cmd in destructive_cmds or cmd.startswith("mkfs")

    raw = _raw(ast)
    paths = _extract_paths(ast)

    # Check for device in raw string or extracted paths
    dev_match = DEVICE_RE.search(raw)
    dev_path = dev_match.group(0) if dev_match else None

    if not dev_path:
        for p in paths:
            if DEVICE_RE.match(p):
                dev_path = p
                break

    if is_destructive and dev_path:
        return {
            "risk": "critical",
            "matched_rule": "dd_mkfs_device",
            "reason": (
                f"{cmd} targeting raw block device '{dev_path}' — "
                f"causes complete, irrecoverable data loss on that device"
            ),
        }

    # Also detect redirection to device node, e.g. cat /dev/urandom > /dev/sda
    if dev_path and (">" in raw or "of=" in raw):
        return {
            "risk": "critical",
            "matched_rule": "dd_mkfs_device",
            "reason": f"Direct write/overwrite to raw block device '{dev_path}'",
        }

    return None


def _rule_kill_pid1(ast: dict, kb_entry: Optional[dict]) -> Optional[dict]:
    """kill -9 on PID 1 or killall/pkill on root processes."""
    cmd = ast.get("command", "")
    flags = ast.get("flags", [])
    args = ast.get("args", [])

    if cmd == "kill":
        has_sigkill = any(f in flags for f in ("-9", "-SIGKILL", "-KILL"))
        if has_sigkill and "1" in args:
            return {
                "risk": "critical",
                "matched_rule": "kill_pid1",
                "reason": "kill -9 on PID 1 (init/systemd) — will crash the entire system immediately",
            }
    elif cmd in ("killall", "pkill"):
        all_tokens = flags + args
        if any(f in flags for f in ("-9", "-SIGKILL", "-KILL")) and ("root" in all_tokens or "1" in all_tokens):
            return {
                "risk": "critical",
                "matched_rule": "kill_pid1",
                "reason": f"{cmd} -9 targeting root processes — will terminate core system services",
            }
    return None


def _rule_base64_eval(ast: dict, kb_entry: Optional[dict]) -> Optional[dict]:
    """Obfuscation: base64, hex-encodings, python/perl one-liners, subshells."""
    raw = _raw(ast)
    raw_lower = raw.lower()
    cmd = ast.get("command", "").lower()

    # 1. Base64 decode piped into eval/bash/sh
    has_b64 = ("base64" in raw_lower and any(d in raw_lower for d in ("-d", "--decode"))) or "cm0glxjm" in raw_lower
    has_exec = any(tok in raw_lower for tok in ("eval", "| bash", "|bash", "| sh", "|sh", "| python", "|python"))
    if has_b64 and has_exec:
        return {
            "risk": "high",
            "matched_rule": "base64_decode_exec",
            "reason": "Obfuscated command: base64-decoded payload is executed via shell — intent cannot be statically verified",
        }

    # 2. Hex escape sequence or subshell evaluation
    if r"\x" in raw or r"$'\x" in raw or "$(" in raw and "base64" in raw_lower:
        if any(e in raw_lower for e in ("eval", "sh", "bash", "python")):
            return {
                "risk": "high",
                "matched_rule": "base64_decode_exec",
                "reason": "Obfuscated command containing hex/base64 subshell evaluation",
            }

    # 3. Interpreter one-liners: python -c / perl -e with system commands
    if cmd in ("python", "python3", "perl") and any(f in ast.get("flags", []) for f in ("-c", "-e")):
        arg_str = " ".join(ast.get("args", []))
        if any(term in arg_str for term in ("os.system", "subprocess", "system(", "exec(")):
            return {
                "risk": "high",
                "matched_rule": "base64_decode_exec",
                "reason": f"{cmd} one-liner attempting system-level command execution",
            }

    # 4. eval with arguments
    if cmd == "eval" and ast.get("args"):
        return {
            "risk": "high",
            "matched_rule": "base64_decode_exec",
            "reason": "eval execution with dynamic argument string",
        }

    return None


def _rule_pipe_curl_wget_to_shell(ast: dict, kb_entry: Optional[dict]) -> Optional[dict]:
    """curl/wget piped into bash/sh/python."""
    raw = _raw(ast)
    raw_lower = raw.lower()
    cmd = ast.get("command", "").lower()
    pipe_to = ast.get("pipe_to", "").lower()

    is_download_cmd = cmd in ("curl", "wget") or "curl " in raw_lower or "wget " in raw_lower

    if not is_download_cmd:
        return None

    shell_targets = ("bash", "sh", "/bin/bash", "/bin/sh", "zsh", "/bin/zsh", "python", "python3")
    if pipe_to and (os.path.basename(pipe_to) in shell_targets or pipe_to in shell_targets):
        return _pipe_result(cmd or "curl/wget")

    pipe_patterns = [r"\|\s*(?:ba)?sh\b", r"\|\s*/bin/(?:ba)?sh\b", r"\|\s*zsh\b", r"\|\s*python\d*\b"]
    for pat in pipe_patterns:
        if re.search(pat, raw_lower):
            return _pipe_result(cmd or "curl/wget")

    return None


def _pipe_result(cmd: str) -> dict:
    return {
        "risk": "high",
        "matched_rule": "pipe_curl_wget_to_shell",
        "reason": (
            f"{cmd} output piped directly to an interpreter — "
            f"executes arbitrary remote code without inspection"
        ),
    }


def _rule_reverse_shell_and_exfil(ast: dict, kb_entry: Optional[dict]) -> Optional[dict]:
    """Detect reverse shell patterns (/dev/tcp, nc -e) and sensitive file exfiltration."""
    raw = _raw(ast)
    raw_lower = raw.lower()

    # Reverse shell triggers
    if "/dev/tcp/" in raw_lower or "/dev/udp/" in raw_lower:
        return {
            "risk": "high",
            "matched_rule": "reverse_shell_detected",
            "reason": "Bash /dev/tcp network socket redirection detected — likely reverse shell attempt",
        }

    if ast.get("command") in ("nc", "netcat") and "-e" in ast.get("flags", []):
        return {
            "risk": "high",
            "matched_rule": "reverse_shell_detected",
            "reason": "Netcat command with -e flag detected — potential reverse shell execution",
        }

    # Sensitive file exfiltration (e.g. curl -X POST -d @/etc/shadow)
    if ast.get("command") in ("curl", "wget") and any("@/etc/shadow" in a or "@/etc/passwd" in a for a in ast.get("args", [])):
        return {
            "risk": "high",
            "matched_rule": "sensitive_file_exfiltration",
            "reason": "Exfiltration of sensitive system credentials file detected via network request",
        }

    return None


def _rule_critical_file_overwrite(ast: dict, kb_entry: Optional[dict]) -> Optional[dict]:
    """Detect overwriting or truncating sensitive system files (/etc/passwd, /etc/shadow, etc.)."""
    raw = _raw(ast)
    cmd = ast.get("command", "")
    paths = _extract_paths(ast)

    target_sens = None
    for p in paths:
        if p in SENSITIVE_FILES or p.startswith("/etc/sudoers"):
            target_sens = p
            break

    if not target_sens:
        for sf in SENSITIVE_FILES:
            if sf in raw:
                target_sens = sf
                break

    if target_sens:
        if cmd == ">" or ">" in raw or "tee" in cmd or "ln" in cmd or "echo" in cmd:
            risk_level = "critical" if any(k in target_sens for k in ("passwd", "sudoers", "shadow", "sysrq")) else "high"
            return {
                "risk": risk_level,
                "matched_rule": "critical_file_overwrite",
                "reason": f"Direct overwrite or modification of sensitive system file '{target_sens}'",
            }

    return None


def _rule_privilege_escalation(ast: dict, kb_entry: Optional[dict]) -> Optional[dict]:
    """Detect SUID bit settings, root account modifications, and sudoers edits."""
    cmd = ast.get("command", "")
    flags = ast.get("flags", [])
    args = ast.get("args", [])
    all_tokens = flags + args
    raw = _raw(ast)

    # 1. chmod +s /bin/bash
    if cmd == "chmod" and any(s in all_tokens for s in ("+s", "4755", "u+s")):
        return {
            "risk": "critical",
            "matched_rule": "privilege_escalation",
            "reason": "chmod SUID (+s) flag detected — creates root privilege escalation backdoor",
        }

    # 2. useradd -u 0 (root equivalent)
    if cmd == "useradd" and any(u in all_tokens or u in raw for u in ("-u", "-u 0")) and "0" in all_tokens:
        return {
            "risk": "critical",
            "matched_rule": "privilege_escalation",
            "reason": "useradd with UID 0 — creates root-equivalent privileged user account",
        }

    # 3. passwd root
    if cmd == "passwd" and "root" in args:
        return {
            "risk": "high",
            "matched_rule": "privilege_escalation",
            "reason": "Attempting to change password for root user",
        }

    # 4. visudo with custom EDITOR environment variable
    if cmd == "visudo" and "EDITOR=" in raw:
        return {
            "risk": "high",
            "matched_rule": "privilege_escalation",
            "reason": "visudo executed with custom EDITOR environment override",
        }

    return None


def _rule_system_disruption(ast: dict, kb_entry: Optional[dict]) -> Optional[dict]:
    """Detect system disruption: sysrq, crontab -r, iptables -F, systemctl isolate rescue."""
    cmd = ast.get("command", "")
    flags = ast.get("flags", [])
    args = ast.get("args", [])
    raw = _raw(ast)

    if "/proc/sysrq-trigger" in raw:
        return {
            "risk": "critical",
            "matched_rule": "system_disruption",
            "reason": "SysRq trigger detected — forces immediate hard system reboot/crash",
        }

    if cmd == "crontab" and "-r" in flags:
        return {
            "risk": "medium",
            "matched_rule": "system_disruption",
            "reason": "crontab -r will remove all scheduled cron jobs for the user",
        }

    if cmd == "iptables" and "-F" in flags:
        return {
            "risk": "high",
            "matched_rule": "system_disruption",
            "reason": "iptables -F flushes all firewall rules — leaves system network exposed",
        }

    if cmd == "systemctl" and "isolate" in flags and "rescue.target" in args:
        return {
            "risk": "high",
            "matched_rule": "system_disruption",
            "reason": "systemctl isolate rescue.target terminates multi-user networking and services",
        }

    return None


# ---------------------------------------------------------------------------
# Fallback: KB-informed risk assessment
# ---------------------------------------------------------------------------

def _rule_kb_risk(ast: dict, kb_entry: Optional[dict]) -> Optional[dict]:
    """Fall back to knowledge-base known_risk, adjusted by context."""
    if kb_entry is None:
        return None

    base_risk = kb_entry.get("known_risk", "low")
    flags = ast.get("flags", [])
    kb_flags = {f["flag"]: f for f in kb_entry.get("flags", [])}

    max_danger = 0
    matched_flags: list[str] = []
    for f in flags:
        if f in kb_flags:
            w = kb_flags[f]["danger_weight"]
            if w > max_danger:
                max_danger = w
            if w >= 5:
                matched_flags.append(f"{f} (danger={w})")

    risk = "low"

    if max_danger >= 8:
        risk = "high"
    elif max_danger >= 5:
        risk = "medium"
    elif max_danger >= 3:
        risk = "medium" if base_risk in ("medium", "high", "critical") else "low"

    if ast.get("is_sudo") and risk in ("low", "medium"):
        risk = _escalate(risk)

    protected = kb_entry.get("protected_paths", [])
    if protected and (matched_flags or (ast.get("is_sudo") and ast.get("is_recursive"))):
        paths = _extract_paths(ast)
        for p in paths:
            np = _normalise_path(p)
            is_exact = np in protected
            is_ancestor = any(pp.startswith(np + "/") or pp == np for pp in protected)
            if is_exact or is_ancestor:
                risk = _escalate(risk)
                matched_flags.append(f"target={np}")
                break

    flag_desc = ", ".join(matched_flags) if matched_flags else "none flagged"
    return {
        "risk": risk,
        "matched_rule": "kb_risk_assessment",
        "reason": f"KB base_risk={base_risk}, dangerous flags: [{flag_desc}]",
    }


_RISK_ORDER = ["low", "medium", "high", "critical"]


def _escalate(risk: str) -> str:
    idx = _RISK_ORDER.index(risk) if risk in _RISK_ORDER else 0
    return _RISK_ORDER[min(idx + 1, len(_RISK_ORDER) - 1)]


# ---------------------------------------------------------------------------
# Rule pipeline — ordered by priority (highest severity first)
# ---------------------------------------------------------------------------

_RULES = [
    _rule_fork_bomb,
    _rule_sudo_recursive_force_critical_path,
    _rule_chmod_777_recursive_system,
    _rule_dd_mkfs_device,
    _rule_kill_pid1,
    _rule_base64_eval,
    _rule_pipe_curl_wget_to_shell,
    _rule_reverse_shell_and_exfil,
    _rule_critical_file_overwrite,
    _rule_privilege_escalation,
    _rule_system_disruption,
    _rule_kb_risk,
]

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_DEFAULT_RESULT: dict = {
    "risk": "low",
    "matched_rule": "default_allow",
    "reason": "No rules matched — command appears benign",
}


def check(ast: dict, kb_entry: Optional[dict] = None) -> dict:
    """Evaluate *ast* against all rules and return the first match."""
    for rule_fn in _RULES:
        result = rule_fn(ast, kb_entry)
        if result is not None:
            return result
    return dict(_DEFAULT_RESULT)
