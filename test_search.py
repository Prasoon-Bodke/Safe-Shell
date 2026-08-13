"""
test_search.py

Unit and benchmark tests for semantic_search.py.
Evaluates vector embedding search accuracy against standard benchmark queries
from test_cases.py.
"""

import unittest
import semantic_search
from test_cases import TEST_CASES


class TestSemanticSearch(unittest.TestCase):
    """Test suite for FAISS semantic search accuracy and API contract."""

    def test_01_index_loaded(self):
        """Verify FAISS index loads and has entry items."""
        semantic_search._ensure_index()
        self.assertIsNotNone(semantic_search._index)
        self.assertIsNotNone(semantic_search._id_map)
        self.assertGreater(semantic_search._index.ntotal, 0)

    def test_02_benchmark_queries(self):
        """Evaluate top-1 and top-3 accuracy against benchmark query test cases."""
        top1_hits = 0
        top3_hits = 0
        total = len(TEST_CASES)

        for query, expected_cmd in TEST_CASES:
            results = semantic_search.search(query, top_k=3)
            self.assertGreater(len(results), 0, f"No results returned for query: '{query}'")

            top_cmds = [r["command"] for r in results]
            if top_cmds[0] == expected_cmd:
                top1_hits += 1
            if expected_cmd in top_cmds:
                top3_hits += 1
            else:
                print(f"[SEARCH MISS] '{query}' -> expected '{expected_cmd}', got {top_cmds}")

        top1_acc = (top1_hits / total) * 100
        top3_acc = (top3_hits / total) * 100

        print(f"\n[Semantic Search Benchmark] Top-1 Accuracy: {top1_acc:.1f}% ({top1_hits}/{total})")
        print(f"[Semantic Search Benchmark] Top-3 Accuracy: {top3_acc:.1f}% ({top3_hits}/{total})")

        # Require at least 80% Top-3 accuracy for test pass
        self.assertGreaterEqual(top3_acc, 80.0, "Top-3 search accuracy below 80% threshold")

    def test_03_result_structure(self):
        """Ensure search returns all required keys in each result dict."""
        results = semantic_search.search("delete a file", top_k=2)
        self.assertGreater(len(results), 0)
        first = results[0]
        required_keys = {"command", "category", "known_risk", "similarity", "entry"}
        for k in required_keys:
            self.assertIn(k, first)
        self.assertIsInstance(first["similarity"], float)

    def test_04_top_k_parameter(self):
        """Test top_k filtering returns exact requested result count."""
        res1 = semantic_search.search("permission", top_k=1)
        res5 = semantic_search.search("permission", top_k=5)
        self.assertEqual(len(res1), 1)
        self.assertEqual(len(res5), min(5, semantic_search._index.ntotal))


if __name__ == "__main__":
    unittest.main()
