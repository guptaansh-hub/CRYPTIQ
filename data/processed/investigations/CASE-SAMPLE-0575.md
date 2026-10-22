# CRYPTIQ Forensic Investigation Report: CASE-SAMPLE-0575

> **Evidentiary Boundary (SIH26183):** Identifying an exchange attribution (direct or via transaction connection)
> indicates that funds reached or are held by exchange infrastructure. It is **NOT** proof that the exchange
> entity itself is fraudulent, complicit, or criminal.

## 1. Case Metadata & Address Validation

- **Case ID:** `CASE-SAMPLE-0575`
- **Investigation Timestamp (UTC):** `2026-10-18T21:03:54.370442+00:00`
- **Suspect Wallet Address:** `34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo`
- **Network / Currency:** `BTC`
- **Canonical Address:** `34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo`
- **Address Format:** `p2sh`
- **Cryptographic Validity:** `VALID`

## 2. Direct Exchange Attribution Findings

- **Attributed Exchange Entity:** **BINANCE**
- **Attribution Confidence:** `service_data` (Verified Service Disclosure)
- **Wallet Label:** binance reserve wallets BTC
- **Reserve / Cold Storage Wallet:** `Yes (Proof-of-Reserves Cluster Definer)`
- **Official Disclosure Source:** [https://www.binance.com/en/blog/community/our-commitment-to-transparency-2895840147147652626](https://www.binance.com/en/blog/community/our-commitment-to-transparency-2895840147147652626)
- **Finding Type:** `DIRECT_EXCHANGE_WALLET_IDENTIFIED`
- **Evidentiary Note:** The victim-reported address itself is directly attributed to a verified exchange entity (e.g. proof-of-reserves cold vault or hot wallet) in official service disclosures. This identifies the address as exchange infrastructure; it is NOT an abuse/scam flag and does NOT imply the exchange entity itself is fraudulent.

## 3. Prior Scam & Abuse Registry Flags

_No prior scam, malware, or phishing abuse records found in verified abuse feeds for this address._

## 4. Transaction Flow Tracing & Downstream Exchange Connections

- **Transaction Graph Status:** `0 transactions indexed` (Empty / No Data Loaded)
- **Live Network Fetching:** `Disabled (Offline Mode)`
> _Note: No transaction graph dataset was loaded. Multi-hop flow tracing was not performed._
> _To trace downstream hops, enable live fetching with `--enable-network-fetching` or pre-load transaction records._

## 5. Methodological & Model Boundaries

- **AML Model Boundary:** Offline Elliptic Random Forest model requires the full 165 graph/local feature vector. Raw on-chain transactions cannot be directly scored without running the full Elliptic topological feature extraction pipeline. Behavioral AML scores are kept strictly distinct from verified exchange entity identity.
- **Attribution Provenance:** All exchange attributions are derived strictly from verified external disclosures (GraphSense service disclosures and EtherScamDB). No exchange identities or fraud linkages were synthetically assumed or inferred from transaction risk classes.
