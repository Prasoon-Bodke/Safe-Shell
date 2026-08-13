# SafeShell

**An AI-Assisted Intent Analysis & Deterministic Safety Engine for Linux Commands**

SafeShell is a prototype safety layer for Linux command-line operations. It analyzes commands before execution, identifies potentially dangerous operations, uses semantic similarity to understand command intent, and applies deterministic security rules to establish a safety floor.

> **Core safety principle:** Semantic AI can provide additional context, but deterministic rules establish the safety floor and should never be overridden by an AI prediction.

---

## 🌟 Key Features

- **Deterministic Safety Rules**  
  Explicit security rules detect dangerous command patterns such as recursive deletion, privileged operations, raw-device writes, fork bombs, and shell execution patterns.

- **Intent Vector Matching**  
  Uses `sentence-transformers` with `all-MiniLM-L6-v2` and FAISS `IndexFlatIP` to identify commands that are semantically related.

- **Linux Knowledge Base**  
  Uses `linux_kb.json` to store command metadata, risk levels, dangerous flags, and protected paths.

- **Risk Classification**  
  Commands are classified into `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` risk levels.

- **Adversarial Edge-Case Audit**  
  Includes a 30-case audit covering dangerous and obfuscated command patterns.

- **Testable Safety Engine**  
  Includes deterministic unit tests for the rules engine.

---

# 🏗 Architecture

The current implemented prototype follows this pipeline:

```text
                Linux Command / Structured Input
                            |
                            v
                 +-----------------------+
                 |   Knowledge Base      |
                 |    linux_kb.json      |
                 +-----------+-----------+
                             |
              +--------------+--------------+
              |                             |
              v                             v
   +-----------------------+      +-----------------------+
   |  Knowledge Base       |      |   Semantic Search     |
   |      Lookup            |      | MiniLM + FAISS        |
   +-----------+-----------+      +-----------+-----------+
               |                              |
               +--------------+---------------+
                              |
                              v
                 +-----------------------+
                 | Deterministic Rules   |
                 |       Engine          |
                 +-----------+-----------+
                             |
                             v
                 +-----------------------+
                 |   Risk / Rule Result  |
                 +-----------------------+
```

### Intended Future Architecture

The core engine can later be extended into a complete interactive safety layer:

```text
User Shell Input
       |
       v
Bashlex Command Parser
       |
       +------------------+
       |                  |
       v                  v
Knowledge Base      Semantic Search
       |                  |
       +--------+---------+
                |
                v
       Deterministic Rules
                |
                v
       Semantic / Policy Fusion
                |
                v
        Context Evaluation
                |
                v
         Decision Engine
          /      |      \
         /       |       \
      ALLOW     WARN    BLOCK
                         |
                         v
                Optional LLM Explanation
```

The LLM should explain and contextualize decisions, but it should **never downgrade a deterministic critical block**.

---

# 🛡 Risk Matrix

| Risk Level | Action | Typical Trigger | Example |
|---|---|---|---|
| **LOW** | `ALLOW` | Read-only or harmless operations | `ls -la` |
| **MEDIUM** | `WARN` | State-changing operations | `rm notes.txt` |
| **HIGH** | `WARN_CONFIRM` | Obfuscation or elevated-risk execution | `curl script \| bash` |
| **CRITICAL** | `BLOCK` | Potentially catastrophic operations | `sudo rm -rf /` |

The exact result is determined by the rules implemented in `rules_engine.py`.

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
├── knowledge_base.py
├── semantic_search.py
├── rules_engine.py
│
├── test_rules_engine.py
├── test_cases.py
├── edge_case_audit.py
│
├── faiss_index.bin
└── faiss_id_map.pkl
```

### Module Overview

| File | Purpose |
|---|---|
| `linux_kb.json` | Linux command knowledge base |
| `knowledge_base.py` | Loads and queries command metadata |
| `semantic_search.py` | Sentence-Transformer embeddings + FAISS search |
| `rules_engine.py` | Deterministic safety-rule evaluation |
| `test_rules_engine.py` | Unit tests for deterministic rules |
| `test_cases.py` | Test case definitions |
| `edge_case_audit.py` | 30-case adversarial safety audit |
| `faiss_index.bin` | Prebuilt FAISS vector index |
| `faiss_id_map.pkl` | Mapping between FAISS vectors and KB entries |
| `requirements.txt` | Python dependencies |
| `LICENSE` | MIT license |

---

# ⚡ Installation

## Requirements

- Python **3.10+**
- Linux is the target environment.
- Windows can be used for development and testing of the Python components.

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

The main dependencies are:

```text
numpy
faiss-cpu
sentence-transformers
```

---

# 🔍 Semantic Search

SafeShell uses:

```text
sentence-transformers/all-MiniLM-L6-v2
```

to generate 384-dimensional embeddings.

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

even though the exact command name is different.

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

If `linux_kb.json` is changed, rebuild the index.

---

# 🧪 Testing

## Rules Engine Tests

Run:

```bash
python test_rules_engine.py
```

or:

```bash
python -m unittest -v test_rules_engine.py
```

The current rules test suite contains **20 test cases** covering dangerous and safe command patterns.

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

This allows the rules engine and semantic-search system to combine general command knowledge with explicit security rules.

---

# 🧠 Deterministic Safety Engine

The deterministic rules engine is the primary security component.

Examples of dangerous patterns include:

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

The rules engine evaluates command structure, arguments, flags, privileges, paths, and known dangerous patterns.

The important security principle is:

```text
AI prediction
     |
     v
Additional context

Deterministic rules
     |
     v
Safety floor
```

An AI component should not be allowed to turn:

```text
CRITICAL
```

into:

```text
LOW
```

---

# 🔐 Security Limitations

SafeShell is currently a **prototype safety-analysis engine**, not a production shell replacement.

The deterministic rule set does not cover every possible Linux command, shell grammar construct, obfuscation technique, or destructive operation.

Therefore:

- Do not use SafeShell as the only protection against destructive commands.
- Do not assume a `LOW` result guarantees that a command is safe.
- Do not treat semantic similarity as proof of safety.
- Do not execute untrusted commands solely because SafeShell allows them.
- Expand and review deterministic rules before using the system as an execution gate.

The adversarial audit is included specifically to make these limitations visible.

---

# 🚧 Current Scope vs Future Work

The current repository contains the core:

```text
Knowledge Base
        +
Semantic Search
        +
Deterministic Rules Engine
        +
Tests
        +
Adversarial Audit
```

Planned integration layers include:

- [ ] Bashlex-based command parser
- [ ] Semantic-fusion / policy module
- [ ] Git and filesystem context collector
- [ ] Final decision engine
- [ ] Textual terminal interface
- [ ] Optional Anthropic Claude explanation layer
- [ ] SQLite audit logging
- [ ] Dry-run / sandboxed execution
- [ ] Broader adversarial rule coverage
- [ ] Full end-to-end integration tests

---

# 🗺 Example Future Workflow

A completed SafeShell system would process:

```bash
sudo rm -rf /etc
```

approximately as:

```text
Raw Command
     |
     v
Parser
     |
     v
Knowledge Base
     |
     v
Semantic Search
     |
     v
Deterministic Rules
     |
     v
CRITICAL
     |
     v
BLOCK
```

The user would receive an explanation such as:

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

# 📜 License

SafeShell is licensed under the **MIT License**.

See [`LICENSE`](LICENSE) for the complete license text.

---

# 🤝 Development

Contributions are welcome.

Before submitting changes:

1. Add or update tests for new safety rules.
2. Run the deterministic test suite.
3. Run the adversarial audit.
4. Update the knowledge base when adding command metadata.
5. Never commit API keys, `.env` files, virtual environments, `.git/`, or Python cache files.

```bash
python test_rules_engine.py
python edge_case_audit.py
```

---

# ⚠️ Safety Notice

SafeShell is experimental security software.

**Never test destructive commands on a real production system.**

Use a disposable virtual machine or isolated environment when developing and testing dangerous-command detection.