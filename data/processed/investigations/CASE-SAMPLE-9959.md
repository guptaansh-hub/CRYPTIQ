# CRYPTIQ Forensic Investigation Report: CASE-SAMPLE-9959

> **Evidentiary Boundary (SIH26183):** Identifying an exchange attribution (direct or via transaction connection)
> indicates that funds reached or are held by exchange infrastructure. It is **NOT** proof that the exchange
> entity itself is fraudulent, complicit, or criminal.

## 1. Case Metadata & Address Validation

- **Case ID:** `CASE-SAMPLE-9959`
- **Investigation Timestamp (UTC):** `2026-10-22T05:59:31.720485+00:00`
- **Suspect Wallet Address:** `bc1p8y2uvfyu7azz4zkl45cza9cyc63q0g3hqgdes5wmzpr2rjq4axas80uelt`
- **Network / Currency:** `BTC`
- **Canonical Address:** `bc1p8y2uvfyu7azz4zkl45cza9cyc63q0g3hqgdes5wmzpr2rjq4axas80uelt`
- **Address Format:** `bech32m_taproot`
- **Cryptographic Validity:** `VALID`

## 2. Direct Exchange Attribution Findings

_The suspect address is NOT directly attributed to any verified exchange entity in official disclosures._

## 3. Prior Scam & Abuse Registry Flags

_No prior scam, malware, or phishing abuse records found in verified abuse feeds for this address._

## 4. Transaction Flow Tracing & Downstream Exchange Connections

- **Transaction Graph Status:** `185 transactions indexed` (Loaded)
- **Live Network Fetching:** `Enabled` (EsploraBitcoinAdapter)
- **Data Source Provenance:** `https://blockstream.info/api`
- **Network Fetch Status:** `SUCCESS` (Cached: `False`)
- **Queried Addresses:** `bc1p8y2uvfyu7azz4zkl45cza9cyc63q0g3hqgdes5wmzpr2rjq4axas80uelt, bc1pnvu4zl5kfc4cke8cm3a69ensy7p35ltzn5rtp5utt5g0teyyrdaqudqnaz, bc1qkvusg7cjtxf3nn5sglzpy3d2a4f46nzwy0s04f, bc1qm5d0yzqwqv8lluhpv56sj9h0fefafty7rvr4h7, bc1qxx8ch8v60lsx96a6sdsu3glzplth7jjn69ekam, bc1qjph9uuc8xqj4h24qwmjhkey054g0el9vd6qg632rc7edvxk8qajqmphhz3, bc1qcxwc46wuzqx3ekwtl7dem60wutnm2wx82max9u, bc1pds3s9gnaf3m0t5vgtlq8qdvk3jtwdrhj6h55c2t05nkzs0zqeh8q73j797, bc1p76w3l6zf2u5sy258wlwxcptjuefea8pwpcddahw62tu2zzjcvhqqzrln24, bc1ptnxf8aal3apeg8r4zysr6k2mhadg833se2dm4nssl7drjlqdh2jqa4tk3p`
- **Total On-Chain Transactions Ingested:** `206`

> [!WARNING]
> **Partial History Notice (`has_more = True`):** The queried address history contains additional
> on-chain transactions beyond the 25-transaction page limit. Analysis reflects the most recent 25
> transactions and is bounded.
| Exchange | Confidence | Destination Wallet | Min Hops | Total Taint Received | Reserve Wallet? |
|---|---|---|---|---|---|
| **BINANCE** | `service_data` | `34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo` | 1 | 0.000164 BTC | Yes (Proof-of-Reserves) |

### Provenance & Source: BINANCE
- **Official Disclosure Source:** [https://www.binance.com/en/blog/community/our-commitment-to-transparency-2895840147147652626](https://www.binance.com/en/blog/community/our-commitment-to-transparency-2895840147147652626)
- **Finding Type:** `TRANSACTION_CONNECTION_ESTABLISHED`
- **Evidentiary Note:** Evidence indicates funds from the suspect address reached an address controlled by this exchange via one or more transaction hops. This establishes a transaction connection / deposit flow; it does NOT prove that the exchange entity itself is fraudulent.


## 5. Methodological & Model Boundaries

- **AML Model Boundary:** Offline Elliptic Random Forest model requires the full 165 graph/local feature vector. Raw on-chain transactions cannot be directly scored without running the full Elliptic topological feature extraction pipeline. Behavioral AML scores are kept strictly distinct from verified exchange entity identity.
- **Attribution Provenance:** All exchange attributions are derived strictly from verified external disclosures (GraphSense service disclosures and EtherScamDB). No exchange identities or fraud linkages were synthetically assumed or inferred from transaction risk classes.
