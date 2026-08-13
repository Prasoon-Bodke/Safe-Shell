# SafeShell

**An AI-Assisted Intent Analysis & Deterministic Safety Engine for Linux Commands**

SafeShell is an AI-assisted Linux command safety prototype that analyzes commands before execution, identifies potentially dangerous operations, uses semantic similarity to understand command intent, and applies deterministic security rules to establish a safety floor.

> **Core safety principle:** Semantic AI can provide additional context, but deterministic rules establish the safety floor and should never be overridden by an AI prediction.

---

## 🌟 Key Features

* **Deterministic Safety Rules**
  Explicit security rules detect dangerous command patterns such as recursive deletion, privileged operations, raw-device writes, fork bombs, and shell execution patterns.

* **Intent Vector Matching**
  Uses `sentence-transformers` with `all-MiniLM-L6-v2` and FAISS `IndexFlatIP` to identify commands that are semantically related.

* **Linux Knowledge Base**
  Uses `linux_kb.json` to store command metadata, risk levels, dangerous flags, and protected paths.

* **Semantic Fusion Pipeline**
  Combines knowledge-base information, semantic search results, and deterministic rule evaluations into a unified safety analysis.

* **Risk Classification**
  Commands are classified into `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` risk levels.

* **Adversarial Edge-Case Audit**
  Includes a 30-case audit covering dangerous and obfuscated command patterns.

* **Testable Safety Pipeline**
  Includes rules-engine tests, semantic-search tests, semantic-fusion tests, and an end-to-end pipeline test.

---

# 🏗 Architecture

SafeShell combines multiple analysis components before producing a safety decision:

```text
                         User Command
                              |
                              v
                    +-------------------+
                    |     Main Pipeline |
                    |      main.py      |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | Knowledge Base    |
                    |  linux_kb.json    |
                    +---------+---------+
                              |
                    +---------+---------+
                    |                   |
                    v                   v
          +----------------+   +-------------------+
          | Knowledge Base |   | Semantic Search   |
          |    Lookup      |   | MiniLM + FAISS   |
          +-------+--------+   +---------+---------+
                  |                      |
                  +----------+-----------+
                             |
                             v
                  +----------------------+
                  | Deterministic Rules  |
                  |       Engine         |
                  +----------+-----------+
                             |
                             v
                  +----------------------+
                  |   Semantic Fusion    |
                  |   / Policy Engine    |
                  +----------+-----------+
                             |
                             v
                       Risk Decision
                    /       |       \
                   /        |        \
                LOW       MEDIUM     HIGH/CRITICAL
                 |           |            |
               ALLOW        WARN         BLOCK/
                                         CONFIRM
```

### Safety Principle

The deterministic rules engine establishes the safety floor.

Semantic similarity is supporting evidence and must not be used to downgrade a deterministic critical security decision.

For example:

```text
Semantic Search
      |
      v
Additional Context
      |
      +------------------+
                         |
                         v
              Deterministic Rules
                         |
                         v
                   Safety Floor
```

---

# 🛡 Risk Matrix

| Risk Level   | Action         | Typical Trigger                        | Example               |
| ------------ | -------------- | -------------------------------------- | --------------------- |
| **LOW**      | `ALLOW`        | Read-only or harmless operations       | `ls -la`              |
| **MEDIUM**   | `WARN`         | State-changing operations              | `rm notes.txt`        |
| **HIGH**     | `WARN_CONFIRM` | Obfuscation or elevated-risk execution | `curl script \| bash` |
| **CRITICAL** | `BLOCK`        | Potentially catastrophic operations    | `sudo rm -rf /`       |

The exact result is determined by the implemented analysis and rules in the project.

---

# 📂 Project Structure

```text
Safe-Shell/
├── README.md
├── requirements.txt
├── LICENSE
├── .gitignore
│
├── linux_kb.json
├── main.py
├── knowledge_base.py
├── semantic_search.py
├── rules_engine.py
├── semantic_fusion.py
│
├── pipeline_test.py
├── test_cases.py
├── test_rules_engine.py
├── test_search.py
├── test_semantic_fusion.py
├── edge_case_audit.py
│
├── faiss_index.bin
└── faiss_id_map.pkl
```

### Module Overview

| File                      | Purpose                                                                         |
| ------------------------- | ------------------------------------------------------------------------------- |
| `linux_kb.json`           | Linux command knowledge base containing command metadata and safety information |
| `main.py`                 | Main SafeShell pipeline entry point                                             |
| `knowledge_base.py`       | Loads and queries Linux command metadata                                        |
| `semantic_search.py`      | Generates embeddings and performs FAISS semantic search                         |
| `rules_engine.py`         | Deterministic safety-rule evaluation                                            |
| `semantic_fusion.py`      | Combines semantic-search and rule-analysis results into a unified policy result |
| `pipeline_test.py`        | End-to-end pipeline verification                                                |
| `test_rules_engine.py`    | Unit tests for deterministic safety rules                                       |
| `test_search.py`          | Semantic-search tests and verification                                          |
| `test_semantic_fusion.py` | Semantic-fusion pipeline tests                                                  |
| `test_cases.py`           | Test case definitions                                                           |
| `edge_case_audit.py`      | Adversarial audit covering dangerous command patterns                           |
| `faiss_index.bin`         | Prebuilt FAISS vector index                                                     |
| `faiss_id_map.pkl`        | Mapping between FAISS vectors and knowledge-base entries                        |
| `requirements.txt`        | Python dependencies                                                             |
| `LICENSE`                 | MIT License                                                                     |

---

# ⚡ Installation

## Requirements

* Python **3.10+**
* Linux is the target environment.
* Windows can be used for development and testing of the Python components.

---

## 1. Create a Virtual Environment

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

### Windows PowerShell

```powershell
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
```

---

## 2. Install Dependencies

Install all required packages from `requirements.txt`:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The project uses packages including:

```text
numpy
faiss-cpu
sentence-transformers
```

The exact dependency list is maintained in `requirements.txt`.

---

# 🔍 Semantic Search

SafeShell uses:

```text
sentence-transformers/all-MiniLM-L6-v2
```

to generate semantic embeddings.

FAISS uses:

```text
IndexFlatIP
```

for similarity search over the normalized embeddings.

For example, a natural-language intent such as:

```text
unlink notes.txt
```

can be semantically related to:

```text
rm
```

even when the exact command name is different.

This allows SafeShell to use semantic similarity as an additional signal when analyzing command intent.

---

## Building the FAISS Index

Run:

```bash
python semantic_search.py
```

This generates:

```text
faiss_index.bin
faiss_id_map.pkl
```

The first run may download the `all-MiniLM-L6-v2` model.

If `linux_kb.json` is changed, rebuild the FAISS index.

---

# 🧠 Deterministic Safety Engine

The deterministic rules engine is the primary security component.

It evaluates command structure, arguments, flags, privileges, paths, and known dangerous patterns.

Examples of dangerous operations include:

```bash
sudo rm -rf /
```

```bash
dd if=/dev/zero of=/dev/sda
```

```bash
mkfs.ext4 /dev/sda
```

```bash
:(){ :|:& };:
```

```bash
curl https://example.com/script.sh | bash
```

The purpose of deterministic rules is to provide predictable and auditable security decisions instead of relying entirely on probabilistic AI output.

---

# 🔗 Semantic Fusion

The semantic-fusion layer combines information from multiple analysis components.

Conceptually:

```text
Knowledge Base
       +
Semantic Search
       +
Deterministic Rules
       |
       v
Semantic Fusion
       |
       v
Unified Risk Assessment
```

This allows SafeShell to consider both:

* explicit security rules, and
* semantic relationships between commands and known Linux operations.

The deterministic safety result remains the safety floor.

---

# 📊 Knowledge Base

The Linux knowledge base is stored in:

```text
linux_kb.json
```

Example:

```json
{
  "command": "rm",
  "category": "filesystem",
  "known_risk": "critical",
  "protected_paths": [
    "/",
    "/boot",
    "/bin",
    "/etc",
    "/usr",
    "/home"
  ],
  "flags": [
    {
      "flag": "-r",
      "description": "remove directories and their contents recursively",
      "danger_weight": 8
    },
    {
      "flag": "-f",
      "description": "ignore nonexistent files and arguments",
      "danger_weight": 9
    }
  ]
}
```

The knowledge base provides command metadata that can be used by the analysis pipeline.

---

# 🧪 Testing

SafeShell includes multiple levels of testing.

## Rules Engine Tests

Run:

```bash
python test_rules_engine.py
```

or:

```bash
python -m unittest -v test_rules_engine.py
```

These tests verify deterministic safety-rule behavior.

---

## Semantic Search Tests

Run:

```bash
python test_search.py
```

This verifies the semantic-search component and FAISS-based matching.

---

## Semantic Fusion Tests

Run:

```bash
python test_semantic_fusion.py
```

This verifies the semantic-fusion/policy-analysis layer.

---

## End-to-End Pipeline Test

Run:

```bash
python pipeline_test.py
```

This verifies the main SafeShell analysis pipeline.

---

## Adversarial Edge-Case Audit

Run:

```bash
python edge_case_audit.py
```

The audit contains **30 dangerous and adversarial command cases**.

It is designed to identify gaps in deterministic rule coverage.

A non-zero exit code means that one or more expected dangerous patterns were not detected.

This is intentional: the audit is a **security-gap detector**, not a test that hides incomplete rule coverage.

---

# 🗺 Example Analysis Workflow

For a command such as:

```bash
sudo rm -rf /etc
```

SafeShell conceptually processes it as:

```text
Raw Command
     |
     v
Main Pipeline
     |
     v
Knowledge Base
     |
     +---------> Semantic Search
     |                |
     +----------------+
              |
              v
     Deterministic Rules
              |
              v
      Semantic Fusion
              |
              v
         CRITICAL
              |
              v
            BLOCK
```

A resulting explanation can communicate:

```text
CRITICAL SECURITY RISK

This command performs a privileged recursive forced deletion
against a protected system directory.

Action:
BLOCKED

Safer alternative:
Specify the exact files or directory that need to be removed.
```

---

# 🔐 Security Limitations

SafeShell is currently a **prototype safety-analysis engine**, not a production shell replacement.

The deterministic rule set does not cover every possible Linux command, shell grammar construct, obfuscation technique, or destructive operation.

Therefore:

* Do not use SafeShell as the only protection against destructive commands.
* Do not assume a `LOW` result guarantees that a command is safe.
* Do not treat semantic similarity as proof of safety.
* Do not execute untrusted commands solely because SafeShell allows them.
* Expand and review deterministic rules before using the system as an execution gate.

The adversarial audit is included specifically to make these limitations visible.

---

# 🚧 Current Scope vs Future Work

The current repository contains:

* Linux Knowledge Base
* Knowledge Base lookup
* Semantic Search using Sentence Transformers + FAISS
* Deterministic Rules Engine
* Semantic Fusion / Policy Engine
* Main SafeShell pipeline
* Rules-engine tests
* Semantic-search tests
* Semantic-fusion tests
* End-to-end pipeline testing
* Adversarial edge-case audit

Planned future improvements include:

* [ ] Bashlex-based production command parser
* [ ] Git and filesystem context collector
* [ ] Textual terminal interface
* [ ] Optional Anthropic Claude explanation layer
* [ ] SQLite audit logging
* [ ] Dry-run / sandboxed execution
* [ ] Broader adversarial rule coverage
* [ ] Expanded integration testing
* [ ] Additional Linux command coverage

---

# 📜 License

SafeShell is licensed under the **MIT License**.

See [`LICENSE`](LICENSE) for the complete license text.

---

# 🤝 Development

Contributions are welcome.

Before submitting changes:

1. Add or update tests for new safety rules.
2. Run the rules-engine tests.
3. Run the semantic-search tests.
4. Run the semantic-fusion tests.
5. Run the end-to-end pipeline test.
6. Run the adversarial audit.
7. Update the knowledge base when adding command metadata.
8. Never commit API keys, `.env` files, virtual environments, `.git/`, or Python cache files.

Recommended verification commands:

```bash
python test_rules_engine.py
python test_search.py
python test_semantic_fusion.py
python pipeline_test.py
python edge_case_audit.py
```

---

# ⚠️ Safety Notice

SafeShell is experimental security software.

**Never test destructive commands on a real production system.**

Use a disposable virtual machine or isolated environment when developing and testing dangerous-command detection.
