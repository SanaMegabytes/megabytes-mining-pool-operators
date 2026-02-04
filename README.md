# Megabytes – mining pool operators guide

This document describes how to operate a mining pool for **Megabytes**, a multi-algorithm blockchain using a **BlockDAG consensus** with **DAGP** and **MHIS** commitments embedded in the coinbase transaction.

This guide is intended for **pool administrators, stratum operators, and infrastructure maintainers**.

Blocks mined through the reference Stratum implementation were validated to correctly preserve DAG parent commitments (DAGP), SegWit commitments, and MNS registrations embedded in the coinbase transaction.  
The pool does not compute or alter DAG data and relies entirely on daemon-provided block templates.

## 1. Overview

Megabytes differs from traditional linear blockchains in several important ways:

- **BlockDAG consensus**: blocks reference multiple parents instead of a single previous block
- **Multi-algorithm mining**: a single daemon can mine and validate multiple PoW algorithms
- **Consensus commitments embedded in the coinbase**:
  - `DAGP` (DAG Parents)
  - `MHIS` (Merkle History Integrity Summary)
  - SegWit commitment

Because of this architecture, **mining pools must not modify block templates provided by the daemon**, except for extranonce insertion.

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

**Key principle**

> The daemon is the authority for DAG selection and block structure.  
> The pool acts as a transport, coordination, and submission layer — **not a DAG decision engine**.

---

## 3. Coinbase Construction (Mandatory)

Megabytes **requires mining pools to use the coinbase transaction provided by the daemon**
via `getblocktemplate.coinbasetxn.data`.

This is **not optional**.

The daemon-generated coinbase already contains:
- DAGP commitments (DAG parents)
- MHIS commitments
- SegWit structure
- Consensus-critical output ordering

Pool software **must NOT rebuild the coinbase manually**.

---

### 3.1 Mandatory Rules

1. Always use `coinbasetxn.data` from `getblocktemplate`
2. Only modify the **scriptSig of `vin[0]`** to insert extranonce
3. Never alter outputs, OP_RETURN entries, or witness data
4. Fail hard if `coinbasetxn.data` is missing
5. Ensure extranonce insertion does not corrupt DAGP or MHIS payloads

---

### 3.2 Reference Implementation (Extranonce Handling)

The following excerpt shows a **reference-safe method** to split the coinbase into
`coinb1` and `coinb2` using a **unique placeholder pattern**.

This example is provided for clarity and validation purposes.

```cpp
static StratumCoinbaseTemplate BuildStratumCoinbaseTemplate(
    const json& gbt,
    const std::string& extranonce1_hex,
    int extranonce2_size)
{
    const int ex1_bytes = (int)extranonce1_hex.size() / 2;
    const int ex2_bytes = extranonce2_size;
    const int extra_bytes = ex1_bytes + ex2_bytes;

    static const uint8_t kPat[] = {0xFA, 0xBF, 0xFA, 0xBF, 0xFA, 0xBF, 0xFA, 0xBF};
    std::vector<unsigned char> extra_placeholder;
    for (int i = 0; i < extra_bytes; ++i)
        extra_placeholder.push_back(kPat[i % sizeof(kPat)]);

    if (!gbt.contains("coinbasetxn") || !gbt["coinbasetxn"].contains("data"))
        throw std::runtime_error("coinbasetxn.data is required");

    CMutableTransaction mtx;
    CDataStream ss(ParseHex(gbt["coinbasetxn"]["data"]), SER_NETWORK, PROTOCOL_VERSION);
    ss >> mtx;

    mtx.vin[0].scriptSig << extra_placeholder;

    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    ss2 << mtx;

    std::vector<uint8_t> raw(ss2.begin(), ss2.end());

    auto it = std::search(raw.begin(), raw.end(),
                          extra_placeholder.begin(), extra_placeholder.end());
    if (it == raw.end())
        throw std::runtime_error("extranonce placeholder not found");

    size_t start = std::distance(raw.begin(), it);
    size_t end   = start + extra_bytes;

    return {
        BytesToHex({raw.begin(), raw.begin() + start}),
        BytesToHex({raw.begin() + end, raw.end()})
    };
}
```

---

### 3.3 Why This Matters

Incorrect coinbase handling may result in:
- Missing DAG parents
- Invalid MHIS commitments
- Silent consensus rejection
- Blocks accepted by miners but rejected by the network

If in doubt: **do not modify the coinbase**.

---

## 4. DAG Responsibility and Block Templates

### 4.1 DAG Parents and Selected Parent

In Megabytes:
- There is no single linear “best chain”
- Each block commits to a **set of DAG parents**
- The daemon selects:
  - the selected parent
  - the DAG parent list
  - blue / red classification

**Pool operators MUST NOT:**
- Compute DAG parents
- Reorder DAG parents
- Replace or remove DAG commitments

All DAG data is already embedded in the daemon-provided coinbase.

---

## 5. Coinbase Transaction Structure (Informational)

A valid Megabytes coinbase may include:

```text
vout[0]  Block reward
vout[n]   OP_RETURN "MHIS"           (Megabytes consensus)
vout[n+1] OP_RETURN "DAGP"           (Megabytes consensus)
vout[n+2] OP_RETURN 0xaa21a9ed[...]  (SegWit commitment, BIP141)
```

These outputs **must remain unchanged**.

---

## 6. DAGP Commitment Format (Informational)

The DAG parents commitment uses an `OP_RETURN` payload:

```text
"DAGP" | version | parent_count | parent_hash_1 | ... | parent_hash_N
```

- `parent_count` is typically 8
- Each parent hash is 32 bytes
- Pools do not parse or validate this payload
- Validation is performed by the daemon

---

## 7. MHIS Commitment (Informational)

MHIS is embedded in the coinbase via `OP_RETURN`.

It cryptographically commits to historical DAG state and is validated by consensus.

**Pools must preserve it unchanged.**

---

## 8. Multi-Algorithm Mining

Megabytes supports multiple PoW algorithms (e.g. Groestl, KAWPOW).

### 8.1 Single Daemon Model

A single daemon can:
- Serve templates for different algorithms
- Accept blocks mined with different algorithms
- Safely mix algorithms in the same DAG

Pools **do not need multiple daemons**.

---

### 8.2 Algorithm Selection

Algorithm selection may occur via:
- `getblocktemplate` parameters
- Miner password hints (classic stratum)
- Protocol-specific stratum (e.g. KAWPOW / RVN-style)

The daemon remains authoritative.

---

## 9. Stratum Job Handling

### 9.1 Job Refresh Policy

Pools SHOULD refresh jobs when:
- A new block is received
- A new template becomes available
- `clean_jobs = true` is required

Because DAG tips may change without height increasing, **frequent refresh is recommended**.

---

### 9.2 Shares vs Blocks

- Shares are validated normally
- A valid share does not guarantee a valid block
- Final DAG validation is performed by the daemon

Pools may accept shares optimistically and submit full blocks only when the PoW target is met.

---

## 10. KAWPOW-Specific Notes

For KAWPOW mining:
- The block header includes the block height
- `nonce64` and `mix_hash` must be serialized exactly
- The daemon verifies the full KAWPOW proof

Pools must submit:
- The full serialized block
- The correct `mix_hash`
- The correct `nonce64`

---

## 11. Common Mistakes (Do Not Do This)

❌ Rebuilding the coinbase manually  
❌ Removing OP_RETURN outputs  
❌ Combining DAGP and MHIS into a single output  
❌ Computing DAG parents in the pool  
❌ Using stale templates for long periods  
❌ Modifying coinbase outputs for “optimization”

All of the above lead to **invalid or sub-optimal blocks**.

---

## 12. Recommended Pool Checklist

Before running on mainnet:

- [ ] `coinbasetxn.data` is used verbatim
- [ ] Only `scriptSig` is modified
- [ ] DAGP and MHIS outputs are preserved
- [ ] Jobs refresh correctly
- [ ] Multiple algorithms are handled correctly
- [ ] Blocks are validated using DAG RPCs

---

## 13. Validation Commands

Pool operators can validate mined blocks using:

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

## 14. Reference Implementation

The project provides a reference Stratum implementation (`megabytes_stratum.cpp`) demonstrating:

- Multi-algorithm support
- DAG-safe coinbase handling
- Correct block submission
- Classic and KAWPOW stratum compatibility

---

## 15. Final Notes

Megabytes is designed so that **existing pool software can be adapted with minimal changes**, provided that the daemon-provided block template is respected.

> If in doubt: **do not modify what the daemon gives you**.

This guarantees correctness across DAG, MHIS, and future consensus upgrades.




