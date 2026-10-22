# Data Leakage Audit and Methodological Limitations

## 1. Temporal Leakage Audit

- **Partition Isolation:** PASSED
  - Overlap Train ∩ Val: `0`
  - Overlap Train ∩ Test: `0`
  - Overlap Val ∩ Test: `0`
- **Strict Temporal Ordering:** PASSED
  - Train max time step: `34` (<= 34)
  - Validation range: `[35, 39]` (35-39)
  - Test range: `[40, 49]` (40-49)
- **Inductive Preprocessing:** Model scalers and hyperparameters are strictly fitted on the training split.

## 2. Graph Connectivity & Cross-Timestep Leakage

- **Total Graph Edges:** `234,355`
- **Cross-Timestep Edges:** `0`
- **Cross-Split Edges (Train ↔ Val/Test):** `0`
- **Graph Isolation Verdict:** PASSED - Completely Disjoint Subgraphs

### Graph Architecture Note
In the original Elliptic dataset, all 234,355 edges exist strictly within single 2-week time steps. There are **zero** edges connecting transactions between different time steps. Consequently, train, validation, and test sets are topologically disjoint subgraphs.

## 3. Dataset-Level Artifacts & Inherent Caveats

### A. Feature Global Pre-Standardization
The published Elliptic dataset features (columns 2-166) were pre-standardized globally across all 49 time steps by the original dataset authors (Weber et al., 2019). While downstream Random Forest inference does not compute further scalers, this global normalization represents a published dataset-level caveat that cannot be undone without unscaled raw transaction metrics.

### B. Unknown Node Participation in Graph Aggregations
Unknown/unlabeled transactions (157,205 nodes) are excluded from training supervision, but their graph degree and flows contributed to the 72 aggregate features computed in the raw dataset. Because all graph edges are strictly intra-timestep (0 cross-timestep edges), no future unknown node information leaked into past time steps.

## 4. Problem Statement Alignment & Critical Limitations (SIH26183)

> **WARNING:** CRITICAL LIMITATION (SIH26183): Binary transaction classification (illicit vs. licit) does NOT identify cryptocurrency exchanges. In the Elliptic dataset, Class 2 (licit) includes legitimate exchanges, miners, and merchants. Illicit classification indicates transaction-level AML risk (e.g. ransomware, darknet), NOT exchange identity or fraud linkage. Exchange identification requires separate wallet clustering, deposit address reuse tracing, and off-chain attribution datasets.

### Technical Distinction between AML Transaction Scoring and Exchange Attribution:
1. **Granularity Mismatch:** Elliptic classifies individual Bitcoin transactions (UTXO transactions). An exchange is a multi-wallet institutional cluster comprising cold vaults, hot wallets, sweep consolidation addresses, and user deposit addresses.
2. **Attribution Mismatch:** In Elliptic, exchanges are categorized as **licit (Class 2)**. A high illicit risk score indicates darknet, ransomware, or scam transactions, not the identity of an exchange.
3. **Required Next Steps for SIH26183:**
   - Entity resolution / multi-input clustering (Heuristic 1 & 2)
   - Deposit address tracing (identifying hops that terminate at an exchange's deposit pool)
   - Tagpack and off-chain attribution databases (e.g. WalletExplorer, EtherscamDB, exchange cluster manifests)
