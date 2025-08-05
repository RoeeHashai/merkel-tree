# Merkle Tree Implementation

This repository contains a Python implementation of a **Merkle Tree**, also known as a hash tree. Merkle Trees are widely used in cryptographic systems such as **blockchains** (e.g., Bitcoin, Ethereum), **distributed storage**, and **version control systems** like Git.

---

## 🌳 What is a Merkle Tree?

A Merkle Tree is a binary tree in which:

- **Leaf nodes** store the cryptographic hash of individual data blocks.
- **Non-leaf nodes** store the hash of their children’s hashes.

This structure enables:

- ✅ **Data Integrity Verification**  
- ⚡ **Efficient Inclusion Proofs (Merkle Proofs)**  
- 🔄 **Low Bandwidth Data Synchronization**

---

## ✨ Features

- 📦 **Tree Construction**: Build a Merkle Tree from a list of data blocks.
- 🌐 **Merkle Root Calculation**: Obtain a single hash that represents the entire dataset.
- 🔍 **Proof Generation**: Produce a Merkle Proof for any data block.
- 🔐 **Proof Verification**: Confirm the inclusion of a data block using its proof and the Merkle root.

---

## 📁 Files Overview

| File                   | Description                                                                |
|------------------------|----------------------------------------------------------------------------|
| `merkle.py`            | Core implementation of the Merkle Tree class and its methods.              |
| `test_merkle_cli.py`   | CLI-based test suite for the Merkle Tree functionality.                    |
| `test_summary_hebrew.md` | Hebrew summary of tests or implementation behavior.                      |

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/RoeeHashai/merkel-tree.git
cd merkel-tree
```

### 2. Basic Example (Python)

```python
from merkle import MerkleTree

data_blocks = ["apple", "banana", "cherry", "date", "elderberry"]

# Build the tree
tree = MerkleTree(data_blocks)

# Get the root hash
merkle_root = tree.get_merkle_root()
print(f"Merkle Root: {merkle_root}")

# Generate proof for 'banana'
proof = tree.generate_proof("banana")
print(f"Proof: {proof}")

# Verify the proof
print(tree.verify_proof("banana", proof, merkle_root))  # True

# Try invalid proof
print(tree.verify_proof("grape", proof, merkle_root))   # False
```

---

## 🧪 Running Tests

Make sure you have `pytest` installed:

```bash
pip install pytest
```

Then run the tests:

```bash
python -m pytest test_merkle_cli.py
```

---

## 👥 Contributors

- **Roee Hashai**
- **Yatir Gross**

---

## 📜 License

This project is open-source and available under the [MIT License](LICENSE) (add this file if desired).
