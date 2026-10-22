# CRYPTIQ Forensic Investigation Report: DEMO-CASE-001

> **Evidentiary Boundary (SIH26183):** Identifying a transaction connection to an exchange wallet
> proves that funds were routed to or through that exchange. It is **NOT** proof that the exchange
> entity itself is fraudulent, complicit, or criminal.

## 1. Case Metadata & Address Validation

- **Case ID:** `DEMO-CASE-001`
- **Investigation Timestamp (UTC):** `2026-10-18T07:01:55.991807+00:00`
- **Suspect Wallet Address:** `34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo`
- **Network / Currency:** `BTC`
- **Canonical Address:** `34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo`
- **Address Format:** `p2sh`
- **Cryptographic Validity:** `VALID`

## 2. Suspect Wallet Prior Abuse & Scam Records

| Source Feed | Category / Abuse | Confidence | Label / Description |
|---|---|---|---|
| https://www.binance.com/en/blog/community/our-commitment-to-transparency-2895840147147652626 | None | service_data | binance reserve wallets BTC |

## 3. Identified Exchange Connections

_No transaction paths connecting to verified exchange reserve wallets within the search depth._

## 4. Methodological & Model Boundaries

- **AML Model Boundary:** Offline Elliptic Random Forest model requires the full 165 graph/local feature vector. Raw on-chain transactions cannot be directly scored without running the full Elliptic topological feature extraction pipeline. Behavioral AML scores are kept strictly distinct from verified exchange entity identity.
- **Attribution Provenance:** All exchange attributions are derived strictly from verified external disclosures (GraphSense service disclosures and EtherScamDB). No exchange identities or fraud linkages were synthetically assumed or inferred from transaction risk classes.
