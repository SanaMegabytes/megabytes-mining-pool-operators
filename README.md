# Megabytes – Mining Pool Operators Guide

This document describes how to operate a mining pool for **Megabytes**, a multi-algorithm blockchain using a **BlockDAG consensus** with **DAGP** and **MHIS** commitments embedded in the coinbase transaction.

This guide is intended for **pool administrators, stratum operators, and infrastructure maintainers**.

Blocks mined through the reference Stratum implementation were validated to correctly preserve DAG parent commitments (DAGP), SegWit commitments, and MNS registrations embedded in the coinbase transaction. 
The pool does not compute or alter DAG data and relies entirely on daemon-provided block templates.
FILE : megabytes_stratum.cpp 

---

## 1. Overview

Megabytes differs from traditional linear blockchains in several important ways:

- **BlockDAG consensus**: blocks reference multiple parents instead of a single previous block
- **Multi-algorithm mining**: a single daemon can mine and validate multiple PoW algorithms
- **Consensus commitments in coinbase**:
  - `DAGP` (DAG Parents)
  - `MHIS` (Merkle History Integrity Summary)
  - SegWit commitment

Because of this, **the pool must not modify block templates provided by the daemon**, except for extranonce insertion.

---

## 2. High-Level Architecture

The recommended architecture is:

```text
Megabytes Daemon
      ↓ getblocktemplate
Mining Pool / Stratum
      ↓ mining.notify
Miners
```

Key rule:

> **The daemon is the authority for DAG selection and block structure.  
> The pool is a transport and validation layer, not a DAG decision engine.**

---

## 3. Block Templates and DAG Responsibility

### 3.1 Selected Parent and DAG Parents

In Megabytes:
- There is no single “best chain” in the classical sense
- Each block commits to a **set of DAG parents**
- The daemon selects:
  - the **selected parent**
  - the **DAG parents list**
  - the **blue/red classification**

**Pool operators MUST NOT:**
- Compute DAG parents
- Reorder DAG parents
- Replace or remove DAG commitments

All DAG data is already included in the daemon-provided coinbase transaction.

---

## 4. Coinbase Transaction Requirements

### 4.1 Mandatory Rule

The pool **MUST use `coinbasetxn.data` exactly as provided by the daemon**.

The only allowed modification is:
- inserting extranonce bytes into `vin[0].scriptSig`

### 4.2 Coinbase Outputs

A valid Megabytes coinbase may include:

- Block reward output
- `OP_RETURN` with **MHIS** commitment
- `OP_RETURN` with **DAGP** commitment
- SegWit commitment output

Example structure:

```text
vout[0]  Block reward
vout[1]  OP_RETURN "MHIS"
vout[2]  OP_RETURN "DAGP"
vout[3]  OP_RETURN SegWit commitment
```

These outputs **must remain unchanged**.

---

## 5. DAGP Commitment Format (Informational)

The DAG parents commitment uses an `OP_RETURN` payload:

```text
"DAGP" | version | parent_count | parent_hash_1 | ... | parent_hash_N
```

- `parent_count` is typically 8
- Each parent hash is 32 bytes
- The pool does not parse or validate this payload
- The daemon validates it during block acceptance

---

## 6. MHIS Commitment (Informational)

The MHIS commitment is also embedded in the coinbase via `OP_RETURN`.

It cryptographically commits to historical chain data and is used by the consensus engine.

**Pools must preserve it unchanged.**

---

## 7. Multi-Algorithm Mining

Megabytes supports multiple PoW algorithms (e.g. Groestl, KAWPOW).

### 7.1 Single Daemon, Multiple Algorithms

A single Megabytes daemon can:
- Provide templates for different algorithms
- Accept blocks mined with different algorithms
- Mix algorithms safely in the same DAG

The pool **does not need multiple daemons**.

---

### 7.2 Algorithm Selection

Algorithm selection happens via:
- `getblocktemplate` parameters
- Miner password hints (classic stratum)
- Protocol-specific stratum (e.g. KAWPOW / RVN-style)

The daemon remains authoritative.

---

## 8. Stratum Job Handling

### 8.1 Job Refresh Policy

Pools SHOULD refresh jobs when:
- A new block is received
- A new template is available
- `clean_jobs = true` is required

Unlike linear chains, **DAG tips may change without height increasing**, so frequent refresh is recommended.

---

### 8.2 Shares vs Blocks

- Shares are validated normally
- A valid share does not guarantee a valid block
- The daemon performs final DAG validation

Pools may safely:
- Accept shares optimistically
- Submit full blocks only when PoW target is met

---

## 9. KAWPOW-Specific Notes

For KAWPOW mining:

- The block header includes the block height
- `nonce64` and `mix_hash` must be serialized exactly as expected
- The daemon verifies the full KAWPOW proof

Pools must submit:
- Full serialized block
- Correct `mix_hash`
- Correct `nonce64`

---

## 10. Common Mistakes (DO NOT DO THIS)

❌ Rebuilding the coinbase manually  
❌ Removing OP_RETURN outputs  
❌ Combining DAGP and MHIS into one output  
❌ Computing DAG parents in the pool  
❌ Using stale templates for long periods  
❌ Modifying coinbase outputs for “optimization”

All of the above will lead to **invalid or sub-optimal blocks**.

---

## 11. Recommended Pool Checklist

Before running on mainnet, verify:

- [ ] `coinbasetxn.data` is used verbatim
- [ ] Only `scriptSig` is modified for extranonce
- [ ] DAGP and MHIS outputs are preserved
- [ ] Jobs refresh correctly on new templates
- [ ] Multiple algorithms are supported correctly
- [ ] Blocks are validated with `getblockdag`

---

## 12. Validation Commands (Daemon)

Pool operators can verify mined blocks using:

```bash
megabytes-cli getblock <blockhash> 2
```

```bash
megabytes-cli getdagmeta <blockhash>
```

```bash
megabytes-cli getblockdag <blockhash>
```

A valid pooled block will:
- Be on the active chain
- Have resolved DAG parents
- Show matching DAG metadata (DB vs runtime)

---

## 13. Reference Implementation

The project provides a **reference stratum implementation** (`stratum_simple.cpp`) demonstrating:

- Multi-algorithm support
- Correct coinbase handling
- DAG-safe block submission
- KAWPOW and classic stratum compatibility

Pool operators may adapt this code for production use.

---

## 14. Final Notes

Megabytes is designed so that **existing pool software can be adapted with minimal changes**, provided that the daemon-provided block template is respected.

If in doubt:

> **Do not modify what the daemon gives you.**

This guarantees correctness across DAG, MHIS, and future consensus upgrades.






