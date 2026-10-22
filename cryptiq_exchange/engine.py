"""Core engine for CRYPTIQ exchange identification and forensic case reporting."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional, Set
import uuid

from .adapters.esplora import EsploraBitcoinAdapter
from .address import canonicalize_address, validate_address
from .entity_registry import EntityRegistry
from .graph import TransactionGraph
from .models import (
    AddressInfo,
    CaseInvestigationReport,
    DirectExchangeAttribution,
    ExchangeConnectionFinding,
    NetworkFetchMetadata,
    TracePath,
)
from .tracer import BlockchainTracer

LOG = logging.getLogger("cryptiq.engine")


class ExchangeIdentificationEngine:
    """Coordinates address validation, flow tracing, and verified exchange identification.

    Enforces strict forensic guidelines:
    - Zero invented attributions: Unverified addresses remain strictly unattributed.
    - Direct exchange attribution is reported separately from downstream multi-hop flows.
    - A verified exchange disclosure (e.g. Binance Proof-of-Reserves) is NEVER categorized as an abuse flag.
    - An exchange match proves transaction connection / flow routing, NOT exchange complicity.
    - Offline Elliptic model requires full 165-feature vector and is not misapplied to raw addresses.
    - Does not claim live tracing was performed unless backed by actual loaded transaction data.
    """

    def __init__(
        self,
        registry: Optional[EntityRegistry] = None,
        graph: Optional[TransactionGraph] = None,
        raw_data_dir: Optional[str | Path] = None,
    ):
        self.registry = registry or EntityRegistry()
        self.graph = graph or TransactionGraph()

        if raw_data_dir is not None:
            self.registry.load_known_raw_tagpacks(raw_data_dir)

    def investigate_suspect_address(
        self,
        suspect_address: str,
        max_hops: int = 4,
        taint_model: str = "haircut",
        min_taint_threshold: float = 1e-6,
        currency_hint: Optional[str] = None,
        case_id: Optional[str] = None,
        enable_network_fetching: bool = False,
        adapter: Optional[EsploraBitcoinAdapter] = None,
        max_fetch_txs_per_address: int = 25,
        max_expansion_addresses: int = 10,
    ) -> CaseInvestigationReport:
        """Runs an investigation for a victim-reported suspect cryptocurrency address.

        Args:
            suspect_address: The suspect address reported by the victim
            max_hops: Maximum forward hops to search for exchange off-ramps (default: 4)
            taint_model: 'haircut' (proportional) or 'fifo'
            min_taint_threshold: Smallest dust amount of taint to propagate
            currency_hint: Optional currency override ('BTC', 'ETH')
            case_id: Optional tracking identifier
            enable_network_fetching: If True, fetches real transactions via Esplora REST API (default: False)
            adapter: Optional pre-configured EsploraBitcoinAdapter instance
            max_fetch_txs_per_address: Maximum transactions to fetch per address (default: 25)
            max_expansion_addresses: Maximum downstream intermediary addresses to query (default: 10)

        Returns:
            A complete CaseInvestigationReport with chain-of-custody findings.
        """
        cid = case_id or f"CRYPTIQ-{uuid.uuid4().hex[:8].upper()}"
        LOG.info("Initiating case %s for suspect address: %s", cid, suspect_address)

        # 1. Address Validation & Classification
        addr_info = validate_address(suspect_address)
        curr = currency_hint or addr_info.network

        report = CaseInvestigationReport(
            case_id=cid,
            suspect_address=suspect_address,
            currency=curr,
            address_validation=addr_info,
            transaction_graph_size=len(self.graph.transactions),
            transaction_graph_loaded=len(self.graph.transactions) > 0,
        )

        if not addr_info.is_valid:
            LOG.warning("Case %s: Address '%s' failed cryptographic validation.", cid, suspect_address)
            return report

        canonical_addr = addr_info.canonical_address

        # 2. Check if the suspect address itself is registered in verified disclosures
        prior_record = self.registry.lookup(canonical_addr, curr)
        if prior_record:
            if prior_record.category == "exchange":
                # Direct Exchange Attribution (NOT an abuse flag!)
                report.direct_exchange_attribution = DirectExchangeAttribution(
                    exchange_name=prior_record.actor,
                    attribution_confidence=prior_record.confidence,
                    source_disclosure=prior_record.source,
                    label=prior_record.label,
                    is_reserve_wallet=prior_record.is_cluster_definer,
                    currency=prior_record.currency,
                )
                LOG.info(
                    "Case %s: Suspect address is directly a verified exchange wallet for '%s' (%s)",
                    cid,
                    prior_record.actor,
                    prior_record.label,
                )
            elif prior_record.category in ("scam", "phishing") or prior_record.abuse is not None:
                # Prior abuse / scam report (from EtherScamDB or abuse feeds)
                report.suspect_address_prior_flags.append(prior_record)
                LOG.info(
                    "Case %s: Suspect address flagged in abuse feed: %s (%s)",
                    cid,
                    prior_record.source,
                    prior_record.label,
                )

        # 3. Handling starting address already attributed to an exchange:
        # If the address is ALREADY directly attributed to an exchange, report the direct attribution
        # separately and do NOT invent transaction paths or make unnecessary network calls.
        if report.direct_exchange_attribution is not None:
            LOG.info(
                "Case %s: Address is directly an exchange wallet (%s). "
                "Skipping multi-hop outbound flow tracing to avoid inventing transaction paths.",
                cid,
                report.direct_exchange_attribution.exchange_name,
            )
            return report

        # 4. Optional Live / Cached Network Fetching via Esplora Adapter
        if enable_network_fetching:
            if curr == "BTC":
                esplora_adapter = adapter or EsploraBitcoinAdapter()
                meta = NetworkFetchMetadata(
                    enabled=True,
                    adapter_name="EsploraBitcoinAdapter",
                    provenance_base_url=esplora_adapter.base_url,
                )
                LOG.info(
                    "Case %s: Network fetching enabled. Fetching Bitcoin address history for %s via Esplora (%s)...",
                    cid,
                    canonical_addr,
                    esplora_adapter.base_url,
                )

                # Fetch suspect address transactions
                fetch_res = esplora_adapter.populate_graph_for_address(
                    canonical_addr, self.graph, max_txs=max_fetch_txs_per_address
                )
                meta.addresses_queried.append(canonical_addr)
                meta.total_transactions_fetched += fetch_res.total_fetched
                meta.has_more = fetch_res.has_more
                meta.cached = fetch_res.cached
                meta.status = fetch_res.status
                meta.error_message = fetch_res.error_message

                # Multi-hop downstream expansion for unhosted intermediary addresses
                if fetch_res.status in ("SUCCESS", "CACHED") and max_hops > 1:
                    queried_addrs: Set[str] = {canonical_addr}
                    current_layer = [canonical_addr]

                    for _ in range(1, max_hops):
                        next_layer: List[str] = []
                        for parent_addr in current_layer:
                            forward_txs = self.graph.get_forward_transactions(parent_addr)
                            for f_tx in forward_txs:
                                for out in f_tx.outputs:
                                    out_addr = out.address
                                    if (
                                        out_addr
                                        and out_addr not in queried_addrs
                                        and not out.is_op_return
                                        and out_addr not in ("OP_RETURN", "NON_STANDARD", "UNRESOLVED", "COINBASE")
                                    ):
                                        # If already an exchange, tracer will stop here; do not fetch forward.
                                        if self.registry.is_exchange(out_addr):
                                            continue
                                        if len(queried_addrs) >= max_expansion_addresses:
                                            break
                                        queried_addrs.add(out_addr)
                                        next_layer.append(out_addr)

                        if not next_layer:
                            break

                        for next_addr in next_layer:
                            if len(meta.addresses_queried) >= max_expansion_addresses:
                                break
                            hop_res = esplora_adapter.populate_graph_for_address(
                                next_addr, self.graph, max_txs=max_fetch_txs_per_address
                            )
                            meta.addresses_queried.append(next_addr)
                            meta.total_transactions_fetched += hop_res.total_fetched
                            if hop_res.has_more:
                                meta.has_more = True
                            if not hop_res.cached:
                                meta.cached = False
                            if hop_res.status in ("RATE_LIMITED", "TIMEOUT", "HTTP_ERROR", "NETWORK_ERROR"):
                                meta.error_message = hop_res.error_message
                                break

                        current_layer = next_layer

                report.network_fetch_metadata = meta
            else:
                report.network_fetch_metadata = NetworkFetchMetadata(
                    enabled=True,
                    status="UNSUPPORTED_NETWORK",
                    error_message=f"Live network fetching is currently supported for Bitcoin via Esplora; network '{curr}' adapter not configured.",
                )
        else:
            report.network_fetch_metadata = NetworkFetchMetadata(
                enabled=False,
                status="OFFLINE",
            )

        # Update graph status in report
        report.transaction_graph_size = len(self.graph.transactions)
        report.transaction_graph_loaded = len(self.graph.transactions) > 0

        # 5. Check transaction graph data availability:
        # Do not claim flow tracing works unless backed by actual loaded transaction data.
        if not report.transaction_graph_loaded:
            LOG.info(
                "Case %s: Transaction graph is empty (0 transactions indexed). "
                "Multi-hop flow tracing requires on-chain transaction data.",
                cid,
            )
            return report

        # 5. Multi-hop Forward Flow Tracing (when graph is available)
        tracer = BlockchainTracer(
            graph=self.graph,
            registry=self.registry,
            taint_model=taint_model,
            max_hops=max_hops,
            min_taint_threshold=min_taint_threshold,
            stop_at_exchange=True,
        )
        paths = tracer.trace_from_suspect(canonical_addr)
        report.paths = paths
        report.total_paths_traced = len(paths)

        # 6. Synthesize Multi-Hop Downstream Exchange Connections
        exchange_paths: Dict[str, List[TracePath]] = {}
        for path in paths:
            if path.reached_exchange and path.exchange_name:
                exchange_paths.setdefault(path.exchange_name, []).append(path)

        for ex_name, ex_path_list in exchange_paths.items():
            first_path = ex_path_list[0]
            attribution = first_path.terminating_attribution

            min_hops = min(p.total_hops for p in ex_path_list)
            total_taint = sum(p.terminating_taint for p in ex_path_list)

            conn = ExchangeConnectionFinding(
                exchange_name=ex_name,
                attribution_confidence=attribution.confidence if attribution else "unverified",
                source_disclosure=attribution.source if attribution else "",
                destination_wallet=first_path.terminating_address,
                destination_label=attribution.label if attribution else ex_name,
                is_reserve_wallet=attribution.is_cluster_definer if attribution else False,
                path_count=len(ex_path_list),
                min_hop_distance=min_hops,
                total_taint_received=total_taint,
                taint_currency=curr,
            )
            report.exchange_connections.append(conn)
            LOG.info(
                "Case %s: Connected to exchange '%s' across %d hops with %.6f %s taint.",
                cid,
                ex_name,
                min_hops,
                total_taint,
                curr,
            )

        return report
