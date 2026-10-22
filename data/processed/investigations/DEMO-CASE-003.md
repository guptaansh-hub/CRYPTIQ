# CRYPTIQ Forensic Investigation Report: DEMO-CASE-003

> **Evidentiary Boundary (SIH26183):** Identifying an exchange attribution (direct or via transaction connection)
> indicates that funds reached or are held by exchange infrastructure. It is **NOT** proof that the exchange
> entity itself is fraudulent, complicit, or criminal.

## 1. Case Metadata & Address Validation

- **Case ID:** `DEMO-CASE-003`
- **Investigation Timestamp (UTC):** `2026-10-18T07:53:08.804165+00:00`
- **Suspect Wallet Address:** `0xD0cC2B24980CBCCA47EF755Da88B220a82291407`
- **Network / Currency:** `ETH`
- **Canonical Address:** `0xd0cc2b24980cbcca47ef755da88b220a82291407`
- **Address Format:** `eth_hex`
- **Cryptographic Validity:** `VALID`

## 2. Direct Exchange Attribution Findings

_The suspect address is NOT directly attributed to any verified exchange entity in official disclosures._

## 3. Prior Scam & Abuse Registry Flags

| Source Feed | Category / Abuse | Confidence | Label / Description |
|---|---|---|---|
| https://cryptoscamdb.org/ | phishing | curated | myelherwallel.com |

## 4. Transaction Flow Tracing & Downstream Exchange Connections

- **Transaction Graph Status:** `0 transactions indexed` (Empty / No Data Loaded)
> _Note: No transaction graph dataset was loaded. Multi-hop flow tracing was not performed._
> _To trace downstream hops, load verified on-chain transaction data (e.g. from a block export or local CSV)._

## 5. Methodological & Model Boundaries

- **AML Model Boundary:** Offline Elliptic Random Forest model requires the full 165 graph/local feature vector. Raw on-chain transactions cannot be directly scored without running the full Elliptic topological feature extraction pipeline. Behavioral AML scores are kept strictly distinct from verified exchange entity identity.
- **Attribution Provenance:** All exchange attributions are derived strictly from verified external disclosures (GraphSense service disclosures and EtherScamDB). No exchange identities or fraud linkages were synthetically assumed or inferred from transaction risk classes.
