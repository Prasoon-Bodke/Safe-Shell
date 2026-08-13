"""
semantic_search.py

Semantic similarity search over the Linux command knowledge base using
sentence-transformers ('all-MiniLM-L6-v2') and a FAISS IndexFlatIP index
(vectors are L2-normalised so inner-product == cosine similarity).

Public API
----------
build_index(kb_entries)   Build (or rebuild) the FAISS index from KB entries.
search(query, top_k=3)    Return the top-k most similar KB entries with scores.

The index and id-to-entry mapping are cached to disk so subsequent runs skip
the embedding step entirely.
"""

from __future__ import annotations

import os
import pickle
from typing import Optional

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_DIR = os.path.dirname(os.path.abspath(__file__))
_INDEX_PATH = os.path.join(_DIR, "faiss_index.bin")
_MAP_PATH = os.path.join(_DIR, "faiss_id_map.pkl")

# ---------------------------------------------------------------------------
# Module-level state (lazy-loaded)
# ---------------------------------------------------------------------------

_model: Optional[SentenceTransformer] = None
_index: Optional[faiss.IndexFlatIP] = None
_id_map: Optional[list[dict]] = None  # position  ->  full KB entry


def _get_model() -> SentenceTransformer:
    """Load the sentence-transformer model (cached after first call)."""
    global _model
    if _model is None:
        _model = SentenceTransformer("all-MiniLM-L6-v2")
    return _model


# ---------------------------------------------------------------------------
# Text representation
# ---------------------------------------------------------------------------

def _entry_to_text(entry: dict) -> str:
    """Convert a KB entry into a rich natural-language description suitable
    for embedding.  Includes the command name, category, risk level, flag
    names *and* their human-readable descriptions so the model can match
    semantic queries like 'delete a file' to 'rm'.
    """
    cmd = entry.get("command", "")
    cat = entry.get("category", "")
    risk = entry.get("known_risk", "")
    flags = entry.get("flags", [])

    parts = [f"{cmd}: Linux {cat} command (risk: {risk})."]

    # Collect flag descriptions — these carry the real semantics
    flag_descs = []
    for f in flags:
        flag_descs.append(f"{f['flag']} — {f['description']}")

    if flag_descs:
        parts.append("Flags: " + "; ".join(flag_descs) + ".")

    protected = entry.get("protected_paths", [])
    if protected:
        parts.append("Protected paths: " + ", ".join(protected[:6]) + ".")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Index management
# ---------------------------------------------------------------------------

def build_index(kb_entries: list[dict]) -> None:
    """Encode every KB entry and store the vectors in a FAISS IndexFlatIP.

    The index and the id-to-entry mapping are persisted to disk so that
    ``search()`` can reload them without re-encoding.

    Parameters
    ----------
    kb_entries : list[dict]
        Each element is a full KB entry dict (as returned by
        ``knowledge_base.lookup()``).
    """
    global _index, _id_map

    model = _get_model()

    texts = [_entry_to_text(e) for e in kb_entries]

    # Encode and L2-normalise so inner-product == cosine similarity
    embeddings = model.encode(texts, convert_to_numpy=True,
                              normalize_embeddings=True)
    embeddings = embeddings.astype(np.float32)

    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)

    # Persist to disk
    faiss.write_index(index, _INDEX_PATH)
    with open(_MAP_PATH, "wb") as fh:
        pickle.dump(kb_entries, fh)

    # Update module state
    _index = index
    _id_map = list(kb_entries)

    print(f"[semantic_search] Built index: {index.ntotal} entries, "
          f"dim={dim}.  Saved to {_INDEX_PATH}")


def _ensure_index() -> None:
    """Load the cached index from disk if it hasn't been loaded yet."""
    global _index, _id_map

    if _index is not None and _id_map is not None:
        return

    if not os.path.exists(_INDEX_PATH) or not os.path.exists(_MAP_PATH):
        raise RuntimeError(
            "FAISS index not found.  Run build_index() first "
            f"(expected {_INDEX_PATH} and {_MAP_PATH})."
        )

    _index = faiss.read_index(_INDEX_PATH)
    with open(_MAP_PATH, "rb") as fh:
        _id_map = pickle.load(fh)

    print(f"[semantic_search] Loaded cached index: "
          f"{_index.ntotal} entries from disk.")


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

def search(query: str, top_k: int = 3) -> list[dict]:
    """Encode *query* and return the ``top_k`` most similar KB entries.

    Parameters
    ----------
    query : str
        Free-text query, e.g. ``"unlink notes.txt"`` or
        ``"wipe the hard drive"``.
    top_k : int
        Number of results to return (default 3).

    Returns
    -------
    list[dict]
        Each element is a dict with keys:
        ``command``, ``category``, ``known_risk``, ``similarity`` (float 0-1),
        and the full ``entry`` dict from the KB.
    """
    _ensure_index()
    assert _index is not None and _id_map is not None

    model = _get_model()

    q_vec = model.encode([query], convert_to_numpy=True,
                         normalize_embeddings=True).astype(np.float32)

    k = min(top_k, _index.ntotal)
    scores, ids = _index.search(q_vec, k)

    results: list[dict] = []
    for score, idx in zip(scores[0], ids[0]):
        if idx < 0:
            continue  # FAISS sentinel for "no result"
        entry = _id_map[idx]
        results.append({
            "command": entry["command"],
            "category": entry["category"],
            "known_risk": entry["known_risk"],
            "similarity": round(float(score), 4),
            "entry": entry,
        })

    return results


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    from knowledge_base import _load_kb, _KB_PATH

    # Load all KB entries
    with open(_KB_PATH, "r", encoding="utf-8") as f:
        entries = json.load(f)

    print("=== Building index ===")
    build_index(entries)

    print("\n=== Search: 'unlink notes.txt' ===")
    results = search("unlink notes.txt", top_k=3)
    for r in results:
        print(f"  {r['command']:12s}  sim={r['similarity']:.4f}  "
              f"risk={r['known_risk']}")

    # Validate that rm is in the results
    top_cmds = [r["command"] for r in results]
    assert "rm" in top_cmds, (
        f"FAIL: 'rm' not in top-3 results for 'unlink notes.txt': {top_cmds}"
    )
    print("\n  PASS: 'rm' found in top results.\n")

    # A few more demo queries
    demos = [
        "wipe the entire hard drive",
        "download and execute a remote script",
        "change file permissions to allow everyone access",
        "force stop a background process",
        "manage startup services",
    ]
    for q in demos:
        print(f"=== Search: '{q}' ===")
        for r in search(q, top_k=3):
            print(f"  {r['command']:12s}  sim={r['similarity']:.4f}  "
                  f"risk={r['known_risk']}")
        print()
