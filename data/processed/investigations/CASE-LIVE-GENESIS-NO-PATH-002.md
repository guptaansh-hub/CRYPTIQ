# CRYPTIQ Forensic Investigation Report: CASE-LIVE-GENESIS-NO-PATH-002

> **Evidentiary Boundary (SIH26183):** Identifying an exchange attribution (direct or via transaction connection)
> indicates that funds reached or are held by exchange infrastructure. It is **NOT** proof that the exchange
> entity itself is fraudulent, complicit, or criminal.

## 1. Case Metadata & Address Validation

- **Case ID:** `CASE-LIVE-GENESIS-NO-PATH-002`
- **Investigation Timestamp (UTC):** `2026-10-18T20:08:12.932077+00:00`
- **Suspect Wallet Address:** `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`
- **Network / Currency:** `BTC`
- **Canonical Address:** `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`
- **Address Format:** `p2pkh`
- **Cryptographic Validity:** `VALID`

## 2. Direct Exchange Attribution Findings

_The suspect address is NOT directly attributed to any verified exchange entity in official disclosures._

## 3. Prior Scam & Abuse Registry Flags

_No prior scam, malware, or phishing abuse records found in verified abuse feeds for this address._

## 4. Transaction Flow Tracing & Downstream Exchange Connections

- **Transaction Graph Status:** `25 transactions indexed` (Loaded)
- **Live Network Fetching:** `Enabled` (EsploraBitcoinAdapter)
- **Data Source Provenance:** `https://blockstream.info/api`
- **Network Fetch Status:** `SUCCESS` (Cached: `False`)
- **Queried Addresses:** `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`
- **Total On-Chain Transactions Ingested:** `27`

> [!WARNING]
> **Partial History Notice (`has_more = True`):** The queried address history contains additional
> on-chain transactions beyond the 25-transaction page limit. Analysis reflects the most recent 25
> transactions and is bounded.
_No transaction paths connecting to verified exchange reserve wallets within the search depth._

## 5. Methodological & Model Boundaries

- **AML Model Boundary:** Offline Elliptic Random Forest model requires the full 165 graph/local feature vector. Raw on-chain transactions cannot be directly scored without running the full Elliptic topological feature extraction pipeline. Behavioral AML scores are kept strictly distinct from verified exchange entity identity.
- **Attribution Provenance:** All exchange attributions are derived strictly from verified external disclosures (GraphSense service disclosures and EtherScamDB). No exchange identities or fraud linkages were synthetically assumed or inferred from transaction risk classes.
