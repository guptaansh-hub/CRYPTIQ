"""Command-line interface for CRYPTIQ exchange identification and case investigation."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from .address import validate_address
from .engine import ExchangeIdentificationEngine
from .entity_registry import EntityRegistry
from .graph import TransactionGraph

LOG = logging.getLogger("cryptiq.cli")


def resolve_raw_dir(raw_arg: Optional[str | Path] = None) -> Path:
    """Locates the directory containing verified GraphSense and EtherScamDB tagpacks."""
    if raw_arg is not None:
        p = Path(raw_arg)
        if (p / "exchange-wallets-binance.yaml").exists() or (p / "exchange-wallets-bybit.yaml").exists():
            return p
        raise FileNotFoundError(f"Tagpack files not found in specified directory: {p}")

    candidates = [
        Path("data/raw"),
        Path("D:/cryptiq-data/cryptiq-data/data/raw"),
        Path("C:/Users/HP/Downloads/cryptiq-data/cryptiq-data/data/raw"),
    ]
    for c in candidates:
        if (c / "exchange-wallets-binance.yaml").exists():
            return c

    raise FileNotFoundError(f"Tagpack files not found in candidate paths: {[str(c) for c in candidates]}")


def format_markdown_report(report_dict: dict) -> str:
    """Renders a readable evidentiary markdown summary of an investigation."""
    lines = [
        f"# CRYPTIQ Forensic Investigation Report: {report_dict['case_id']}",
        "",
        "> **Evidentiary Boundary (SIH26183):** Identifying an exchange attribution (direct or via transaction connection)",
        "> indicates that funds reached or are held by exchange infrastructure. It is **NOT** proof that the exchange",
        "> entity itself is fraudulent, complicit, or criminal.",
        "",
        "## 1. Case Metadata & Address Validation",
        "",
        f"- **Case ID:** `{report_dict['case_id']}`",
        f"- **Investigation Timestamp (UTC):** `{report_dict['created_at_utc']}`",
        f"- **Suspect Wallet Address:** `{report_dict['suspect_address']}`",
        f"- **Network / Currency:** `{report_dict['currency']}`",
    ]

    addr = report_dict.get("address_validation")
    if addr:
        lines.extend([
            f"- **Canonical Address:** `{addr['canonical']}`",
            f"- **Address Format:** `{addr['format']}`",
            f"- **Cryptographic Validity:** `{'VALID' if addr['is_valid'] else 'INVALID'}`",
        ])

    lines.extend([
        "",
        "## 2. Direct Exchange Attribution Findings",
        "",
    ])

    direct = report_dict.get("direct_exchange_attribution")
    if direct:
        lines.extend([
            f"- **Attributed Exchange Entity:** **{direct['exchange_name'].upper()}**",
            f"- **Attribution Confidence:** `{direct['attribution_confidence']}` (Verified Service Disclosure)",
            f"- **Wallet Label:** {direct['label']}",
            f"- **Reserve / Cold Storage Wallet:** `{'Yes (Proof-of-Reserves Cluster Definer)' if direct['is_reserve_wallet'] else 'No'}`",
            f"- **Official Disclosure Source:** [{direct['source_disclosure']}]({direct['source_disclosure']})",
            f"- **Finding Type:** `{direct['finding_type']}`",
            f"- **Evidentiary Note:** {direct['evidentiary_note']}",
        ])
    else:
        lines.append("_The suspect address is NOT directly attributed to any verified exchange entity in official disclosures._")

    lines.extend([
        "",
        "## 3. Prior Scam & Abuse Registry Flags",
        "",
    ])

    priors = report_dict.get("suspect_prior_abuse_flags", [])
    if priors:
        lines.append("| Source Feed | Category / Abuse | Confidence | Label / Description |")
        lines.append("|---|---|---|---|")
        for p in priors:
            lines.append(f"| {p.get('source')} | {p.get('abuse')} | {p.get('confidence')} | {p.get('label')} |")
    else:
        lines.append("_No prior scam, malware, or phishing abuse records found in verified abuse feeds for this address._")

    lines.extend([
        "",
        "## 4. Transaction Flow Tracing & Downstream Exchange Connections",
        "",
    ])

    g_status = report_dict.get("transaction_graph_status", {})
    net_meta = report_dict.get("network_fetch_metadata")
    indexed_txs = g_status.get("transactions_indexed", 0)
    lines.append(f"- **Transaction Graph Status:** `{indexed_txs} transactions indexed` ({'Loaded' if g_status.get('graph_loaded') else 'Empty / No Data Loaded'})")

    if net_meta and net_meta.get("enabled"):
        lines.append(f"- **Live Network Fetching:** `Enabled` ({net_meta.get('adapter_name', 'Esplora')})")
        lines.append(f"- **Data Source Provenance:** `{net_meta.get('provenance_base_url')}`")
        lines.append(f"- **Network Fetch Status:** `{net_meta.get('status')}` (Cached: `{net_meta.get('cached')}`)")
        lines.append(f"- **Queried Addresses:** `{', '.join(net_meta.get('addresses_queried', []))}`")
        lines.append(f"- **Total On-Chain Transactions Ingested:** `{net_meta.get('total_transactions_fetched')}`")
        if net_meta.get("has_more"):
            lines.append("")
            lines.append("> [!WARNING]")
            lines.append("> **Partial History Notice (`has_more = True`):** The queried address history contains additional")
            lines.append("> on-chain transactions beyond the 25-transaction page limit. Analysis reflects the most recent 25")
            lines.append("> transactions and is bounded.")
        if net_meta.get("error_message"):
            lines.append("")
            lines.append(f"> [!WARNING]\n> **Network Fetch Notice:** {net_meta.get('error_message')}")
    else:
        lines.append("- **Live Network Fetching:** `Disabled (Offline Mode)`")

    if not g_status.get("graph_loaded"):
        if net_meta and net_meta.get("status") == "EMPTY_HISTORY":
            lines.append("> _Note: The queried address has 0 recorded transactions on the Bitcoin network._")
        else:
            lines.append("> _Note: No transaction graph dataset was loaded. Multi-hop flow tracing was not performed._")
            lines.append("> _To trace downstream hops, enable live fetching with `--enable-network-fetching` or pre-load transaction records._")
    elif direct:
        lines.append("> _Note: The starting address is already an identified exchange wallet. Outbound multi-hop tracing was skipped to avoid inventing transaction paths._")
    else:
        conns = report_dict.get("exchange_connections", [])
        if conns:
            lines.append("| Exchange | Confidence | Destination Wallet | Min Hops | Total Taint Received | Reserve Wallet? |")
            lines.append("|---|---|---|---|---|---|")
            for c in conns:
                is_res = "Yes (Proof-of-Reserves)" if c.get("is_reserve_wallet") else "No"
                lines.append(
                    f"| **{c.get('exchange_name').upper()}** | `{c.get('attribution_confidence')}` | "
                    f"`{c.get('destination_wallet')}` | {c.get('min_hop_distance')} | "
                    f"{c.get('total_taint_received'):.6f} {c.get('taint_currency')} | {is_res} |"
                )
            lines.append("")
            for c in conns:
                lines.append(f"### Provenance & Source: {c.get('exchange_name').upper()}")
                lines.append(f"- **Official Disclosure Source:** [{c.get('source_disclosure')}]({c.get('source_disclosure')})")
                lines.append(f"- **Finding Type:** `{c.get('finding_type')}`")
                lines.append(f"- **Evidentiary Note:** {c.get('evidentiary_note')}")
                lines.append("")
        else:
            lines.append("_No transaction paths connecting to verified exchange reserve wallets within the search depth._")

    lines.extend([
        "",
        "## 5. Methodological & Model Boundaries",
        "",
        f"- **AML Model Boundary:** {report_dict.get('aml_transaction_risk_note')}",
        f"- **Attribution Provenance:** {report_dict.get('disclaimer')}",
        "",
    ])

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CRYPTIQ: Real-Time Identification of Fraud-Linked Cryptocurrency Exchanges."
    )
    parser.add_argument(
        "--address",
        required=True,
        help="Victim-reported suspect cryptocurrency wallet address to investigate.",
    )
    parser.add_argument(
        "--raw-dir",
        default=None,
        help="Path to directory containing verified tagpack YAML files. Auto-detected if omitted.",
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=4,
        help="Maximum forward transaction hops to trace. Default: 4",
    )
    parser.add_argument(
        "--taint-model",
        choices=["haircut", "fifo"],
        default="haircut",
        help="Taint calculation algorithm: 'haircut' (proportional) or 'fifo'. Default: haircut",
    )
    parser.add_argument(
        "--out-dir",
        default="data/processed/investigations",
        help="Directory to save case reports. Default: data/processed/investigations",
    )
    parser.add_argument(
        "--case-id",
        default=None,
        help="Optional case identifier (e.g. CASE-2026-SIH26183-001).",
    )
    parser.add_argument(
        "--enable-network-fetching",
        action="store_true",
        default=False,
        help="Opt-in to fetch real Bitcoin transaction history via Esplora REST API (disabled by default).",
    )
    parser.add_argument(
        "--esplora-base-url",
        default="https://blockstream.info/api",
        help="Base URL for Blockstream Esplora / Mempool.space REST API. Default: https://blockstream.info/api",
    )
    parser.add_argument(
        "--cache-dir",
        default="data/cache/esplora",
        help="Directory to cache fetched transactions and address histories. Default: data/cache/esplora",
    )
    parser.add_argument(
        "--max-fetch-txs",
        type=int,
        default=25,
        help="Maximum transactions to fetch per address (Esplora page limit is 25). Default: 25",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    raw_dir = resolve_raw_dir(args.raw_dir)
    LOG.info("Using verified attribution tagpack directory: %s", raw_dir)

    # Initialize Engine with verified tagpacks
    reg = EntityRegistry()
    loaded_tagpacks = reg.load_known_raw_tagpacks(raw_dir)
    LOG.info("Loaded %d verified TagPacks (%s)", len(loaded_tagpacks), list(loaded_tagpacks.keys()))

    engine = ExchangeIdentificationEngine(registry=reg)

    # Setup adapter if network fetching enabled
    adapter = None
    if args.enable_network_fetching:
        from .adapters.esplora import EsploraBitcoinAdapter
        adapter = EsploraBitcoinAdapter(
            base_url=args.esplora_base_url,
            cache_dir=args.cache_dir,
        )

    # Run investigation
    report = engine.investigate_suspect_address(
        suspect_address=args.address,
        max_hops=args.max_hops,
        taint_model=args.taint_model,
        case_id=args.case_id,
        enable_network_fetching=args.enable_network_fetching,
        adapter=adapter,
        max_fetch_txs_per_address=args.max_fetch_txs,
    )

    report_dict = report.to_dict()

    # Save outputs
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / f"{report.case_id}.json"
    md_path = out_dir / f"{report.case_id}.md"

    json_path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
    md_content = format_markdown_report(report_dict)
    md_path.write_text(md_content, encoding="utf-8")

    LOG.info("Investigation finished.")
    LOG.info("JSON Case File: %s", json_path)
    LOG.info("Markdown Report: %s", md_path)

    # Console summary
    print("\n" + "=" * 70)
    print(f"CASE INVESTIGATION SUMMARY: {report.case_id}")
    print("=" * 70)
    print(f"Suspect Address:      {report.suspect_address}")
    print(f"Network / Currency:   {report.currency}")
    print(f"Cryptographic Valid:  {report.address_validation.is_valid if report.address_validation else False}")
    
    if report.direct_exchange_attribution:
        d = report.direct_exchange_attribution
        print(f"\n[DIRECT EXCHANGE ATTRIBUTION DETECTED]")
        print(f"  Exchange Entity:    {d.exchange_name.upper()}")
        print(f"  Confidence Tier:    {d.attribution_confidence} (Official Service Disclosure)")
        print(f"  Wallet Label:       {d.label}")
        print(f"  Reserve Wallet:     {'Yes' if d.is_reserve_wallet else 'No'}")
        print(f"  Source Disclosure:  {d.source_disclosure}")
        print(f"  Finding:            {d.finding_type}")
    else:
        print(f"Direct Exchange:      None (Address is not a verified exchange wallet)")

    print(f"Prior Abuse Flags:    {len(report.suspect_address_prior_flags)}")
    for flag in report.suspect_address_prior_flags:
        print(f"  - Abuse Category:   {flag.abuse} ({flag.label}) | Source: {flag.source}")

    net_desc = "Disabled (Offline Mode)"
    if report.network_fetch_metadata and report.network_fetch_metadata.enabled:
        net_desc = f"Enabled ({report.network_fetch_metadata.status}, Cached: {report.network_fetch_metadata.cached}, Ingested: {report.network_fetch_metadata.total_transactions_fetched})"
    print(f"Network Fetching:     {net_desc}")
    if report.network_fetch_metadata and report.network_fetch_metadata.has_more:
        print("                      [NOTICE: Address history is partial (has_more=True, >=25 txs)]")
    if report.network_fetch_metadata and report.network_fetch_metadata.error_message:
        print(f"                      [ERROR: {report.network_fetch_metadata.error_message}]")

    g_status = "0 loaded (Empty)" if not report.transaction_graph_loaded else f"{report.transaction_graph_size} indexed"
    print(f"Transaction Graph:    {g_status}")
    print(f"Downstream Paths:     {report.total_paths_traced}")
    print(f"Exchange Connections: {len(report.exchange_connections)}")

    for conn in report.exchange_connections:
        print(f"\n  -> Downstream Exchange: {conn.exchange_name.upper()}")
        print(f"     Attribution Tier:    {conn.attribution_confidence}")
        print(f"     Destination Wallet:  {conn.destination_wallet}")
        print(f"     Min Hop Distance:    {conn.min_hop_distance}")
        print(f"     Total Taint Flow:    {conn.total_taint_received:.6f} {conn.taint_currency}")
        print(f"     Finding Type:        {conn.finding_type}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
