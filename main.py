"""
main.py

Interactive Command Line Interface for SafeShell.

Allows users to analyze Linux commands interactively in real time.
Evaluates command intent, flags, knowledge base facts, FAISS semantic search matches,
and the deterministic safety rules engine to display a detailed verdict.

Usage
-----
Interactive mode:
    python main.py

Single command mode:
    python main.py "sudo rm -rf /etc"
"""

import sys
import semantic_fusion

import os
import sys

# Ensure UTF-8 output encoding for Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ANSI color escape codes for terminal formatting
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_CYAN = "\033[96m"
COLOR_BLUE = "\033[94m"


def format_risk(risk: str) -> str:
    """Format risk level string with ANSI color coding."""
    risk_upper = risk.upper()
    if risk == "critical":
        return f"{COLOR_BOLD}{COLOR_RED}[CRITICAL]{COLOR_RESET}"
    elif risk == "high":
        return f"{COLOR_BOLD}{COLOR_RED}[HIGH]{COLOR_RESET}"
    elif risk == "medium":
        return f"{COLOR_BOLD}{COLOR_YELLOW}[MEDIUM]{COLOR_RESET}"
    else:
        return f"{COLOR_BOLD}{COLOR_GREEN}[LOW]{COLOR_RESET}"


def format_action(action: str) -> str:
    """Format policy action string with ANSI color coding."""
    if action == "BLOCK":
        return f"{COLOR_BOLD}{COLOR_RED}[BLOCK]{COLOR_RESET}"
    elif action == "WARN_CONFIRM":
        return f"{COLOR_BOLD}{COLOR_RED}[WARN & CONFIRM]{COLOR_RESET}"
    elif action == "WARN":
        return f"{COLOR_BOLD}{COLOR_YELLOW}[WARN]{COLOR_RESET}"
    else:
        return f"{COLOR_BOLD}{COLOR_GREEN}[ALLOW]{COLOR_RESET}"


def print_analysis(result: dict) -> None:
    """Print structured visual report for analyzed command."""
    cmd = result["raw_command"]
    risk = result["final_risk"]
    action = result["action"]
    rule = result["rule_result"]["matched_rule"]
    explanation = result["explanation"]
    alternative = result["suggested_alternative"]
    matches = result["semantic_matches"]

    print("\n" + "=" * 70)
    print(f"{COLOR_BOLD}{COLOR_CYAN}  SAFESHELL COMMAND SAFETY ANALYSIS{COLOR_RESET}")
    print("=" * 70)
    print(f"  {COLOR_BOLD}Command:{COLOR_RESET}     {cmd}")
    print(f"  {COLOR_BOLD}Risk Level:{COLOR_RESET}  {format_risk(risk)}")
    print(f"  {COLOR_BOLD}Action:{COLOR_RESET}      {format_action(action)}")
    print(f"  {COLOR_BOLD}Matched Rule:{COLOR_RESET}{rule}")
    print(f"  {COLOR_BOLD}Verdict:{COLOR_RESET}     {explanation}")
    print(f"  {COLOR_BOLD}Alternative:{COLOR_RESET} {alternative}")

    if matches:
        print(f"\n  {COLOR_BOLD}Top Vector Concept Matches (FAISS):{COLOR_RESET}")
        for idx, m in enumerate(matches[:3], 1):
            print(f"   {idx}. {m['command']:<12s} (similarity: {m['similarity']:.4f}, risk: {m['known_risk']})")
    print("=" * 70 + "\n")


def interactive_loop():
    """Run interactive REPL loop for evaluating commands."""
    print(f"{COLOR_BOLD}{COLOR_CYAN}")
    print("======================================================================")
    print("                      SAFESHELL INTERACTIVE CLI                       ")
    print("   Type any Linux command to analyze risk level & safer alternatives. ")
    print("   Type 'exit', 'quit', or press Ctrl+C to stop.                     ")
    print("======================================================================")
    print(f"{COLOR_RESET}")

    while True:
        try:
            cmd = input(f"{COLOR_BOLD}SafeShell > {COLOR_RESET}").strip()
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit", "q"):
                print("Exiting SafeShell CLI. Stay safe!")
                break

            result = semantic_fusion.fuse(cmd)
            print_analysis(result)

        except (KeyboardInterrupt, EOFError):
            print("\nExiting SafeShell CLI. Stay safe!")
            break


def main():
    if len(sys.argv) > 1:
        raw_cmd = " ".join(sys.argv[1:])
        result = semantic_fusion.fuse(raw_cmd)
        print_analysis(result)
    else:
        interactive_loop()


if __name__ == "__main__":
    main()
