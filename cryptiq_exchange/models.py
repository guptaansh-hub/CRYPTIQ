"""Data models and schemas for CRYPTIQ exchange identification."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class AddressInfo:
    """Validated blockchain address representation."""
    raw_address: str
    canonical_address: str
    network: str  # "BTC", "ETH", "UNKNOWN"
    address_format: str  # "p2pkh", "p2sh", "bech32_segwit", "bech32m_taproot", "eth_hex", "invalid"
    is_valid: bool


@dataclass(frozen=True)
class AttributionRecord:
    """Verified entity attribution record from external disclosures (TagPacks)."""
    address: str
    currency: str
    actor: str  # e.g. "binance", "bybit"
    category: str  # e.g. "exchange", "scam", "phishing"
    confidence: str  # "service_data", "curated", "unverified"
    source: str  # URL or public disclosure reference
    label: str
    is_cluster_definer: bool = False
    abuse: Optional[str] = None  # e.g. "phishing", "ransomware" if scam


@dataclass
class DirectExchangeAttribution:
    """Direct attribution when the investigated address itself belongs to a verified exchange."""
    exchange_name: str
    attribution_confidence: str
    source_disclosure: str
    label: str
    is_reserve_wallet: bool
    currency: str
    finding_type: str = "DIRECT_EXCHANGE_WALLET_IDENTIFIED"
    evidentiary_note: str = (
        "The victim-reported address itself is directly attributed to a verified exchange "
        "entity (e.g. proof-of-reserves cold vault or hot wallet) in official service disclosures. "
        "This identifies the address as exchange infrastructure; it is NOT an abuse/scam flag "
        "and does NOT imply the exchange entity itself is fraudulent."
    )


@dataclass
class HopStep:
    """Individual transaction step along a tracing path."""
    hop_number: int
    txid: str
    from_address: str
    to_address: str
    value: float  # In native units (BTC or ETH)
    taint_ratio: float  # Inflow taint percentage [0.0, 1.0]
    taint_amount: float  # Value * taint_ratio
    block_height: Optional[int] = None
    timestamp: Optional[str] = None
    attribution: Optional[AttributionRecord] = None


@dataclass
class TracePath:
    """Complete path from suspect address to a destination address."""
    path_id: str
    steps: List[HopStep]
    terminating_address: str
    terminating_attribution: Optional[AttributionRecord]
    total_hops: int
    initial_taint_sent: float
    terminating_value: float
    terminating_taint: float

    @property
    def reached_exchange(self) -> bool:
        if self.terminating_attribution:
            return self.terminating_attribution.category == "exchange"
        return False

    @property
    def exchange_name(self) -> Optional[str]:
        if self.reached_exchange and self.terminating_attribution:
            return self.terminating_attribution.actor
        return None


@dataclass
class ExchangeConnectionFinding:
    """Finding documenting a multi-hop connection between suspect address and an exchange."""
    exchange_name: str
    attribution_confidence: str
    source_disclosure: str
    destination_wallet: str
    destination_label: str
    is_reserve_wallet: bool
    path_count: int
    min_hop_distance: int
    total_taint_received: float
    taint_currency: str
    finding_type: str = "TRANSACTION_CONNECTION_ESTABLISHED"
    evidentiary_note: str = (
        "Evidence indicates funds from the suspect address reached an address controlled by "
        "this exchange via one or more transaction hops. This establishes a transaction "
        "connection / deposit flow; it does NOT prove that the exchange entity itself is fraudulent."
    )


@dataclass
class NetworkFetchMetadata:
    """Metadata regarding live network / adapter transaction fetching."""
    enabled: bool = False
    adapter_name: Optional[str] = None
    status: str = "OFFLINE"  # "OFFLINE", "SUCCESS", "EMPTY_HISTORY", "RATE_LIMITED", "TIMEOUT", "HTTP_ERROR", "NETWORK_ERROR", "PARTIAL"
    addresses_queried: List[str] = field(default_factory=list)
    total_transactions_fetched: int = 0
    has_more: bool = False  # Indicates partial history due to pagination
    cached: bool = False
    error_message: Optional[str] = None
    provenance_base_url: Optional[str] = None


@dataclass
class CaseInvestigationReport:
    """Final comprehensive evidentiary case report for a victim-reported address."""
    case_id: str
    suspect_address: str
    currency: str
    created_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    address_validation: Optional[AddressInfo] = None
    direct_exchange_attribution: Optional[DirectExchangeAttribution] = None
    suspect_address_prior_flags: List[AttributionRecord] = field(default_factory=list)
    transaction_graph_size: int = 0
    transaction_graph_loaded: bool = False
    total_paths_traced: int = 0
    exchange_connections: List[ExchangeConnectionFinding] = field(default_factory=list)
    paths: List[TracePath] = field(default_factory=list)
    network_fetch_metadata: Optional[NetworkFetchMetadata] = None
    aml_transaction_risk_note: str = (
        "Offline Elliptic Random Forest model requires the full 165 graph/local feature vector. "
        "Raw on-chain transactions cannot be directly scored without running the full Elliptic "
        "topological feature extraction pipeline. Behavioral AML scores are kept strictly distinct "
        "from verified exchange entity identity."
    )
    disclaimer: str = (
        "All exchange attributions are derived strictly from verified external disclosures "
        "(GraphSense service disclosures and EtherScamDB). No exchange identities or fraud "
        "linkages were synthetically assumed or inferred from transaction risk classes."
    )

    def to_dict(self) -> Dict[str, Any]:
        """Converts report to serializable dictionary."""
        return {
            "case_id": self.case_id,
            "suspect_address": self.suspect_address,
            "currency": self.currency,
            "created_at_utc": self.created_at_utc,
            "address_validation": {
                "raw": self.address_validation.raw_address,
                "canonical": self.address_validation.canonical_address,
                "network": self.address_validation.network,
                "format": self.address_validation.address_format,
                "is_valid": self.address_validation.is_valid,
            } if self.address_validation else None,
            "direct_exchange_attribution": {
                "exchange_name": self.direct_exchange_attribution.exchange_name,
                "attribution_confidence": self.direct_exchange_attribution.attribution_confidence,
                "source_disclosure": self.direct_exchange_attribution.source_disclosure,
                "label": self.direct_exchange_attribution.label,
                "is_reserve_wallet": self.direct_exchange_attribution.is_reserve_wallet,
                "currency": self.direct_exchange_attribution.currency,
                "finding_type": self.direct_exchange_attribution.finding_type,
                "evidentiary_note": self.direct_exchange_attribution.evidentiary_note,
            } if self.direct_exchange_attribution else None,
            "suspect_prior_abuse_flags": [
                {
                    "label": f.label,
                    "abuse": f.abuse,
                    "source": f.source,
                    "confidence": f.confidence,
                }
                for f in self.suspect_address_prior_flags
            ],
            "transaction_graph_status": {
                "transactions_indexed": self.transaction_graph_size,
                "graph_loaded": self.transaction_graph_loaded,
                "network_fetching_enabled": self.network_fetch_metadata.enabled if self.network_fetch_metadata else False,
                "network_fetch_status": self.network_fetch_metadata.status if self.network_fetch_metadata else "OFFLINE",
                "has_more": self.network_fetch_metadata.has_more if self.network_fetch_metadata else False,
                "total_fetched": self.network_fetch_metadata.total_transactions_fetched if self.network_fetch_metadata else 0,
                "error_message": self.network_fetch_metadata.error_message if self.network_fetch_metadata else None,
            },
            "network_fetch_metadata": {
                "enabled": self.network_fetch_metadata.enabled,
                "adapter_name": self.network_fetch_metadata.adapter_name,
                "status": self.network_fetch_metadata.status,
                "addresses_queried": self.network_fetch_metadata.addresses_queried,
                "total_transactions_fetched": self.network_fetch_metadata.total_transactions_fetched,
                "has_more": self.network_fetch_metadata.has_more,
                "cached": self.network_fetch_metadata.cached,
                "error_message": self.network_fetch_metadata.error_message,
                "provenance_base_url": self.network_fetch_metadata.provenance_base_url,
            } if self.network_fetch_metadata else None,
            "total_paths_traced": self.total_paths_traced,
            "exchange_connections": [
                {
                    "exchange_name": conn.exchange_name,
                    "attribution_confidence": conn.attribution_confidence,
                    "source_disclosure": conn.source_disclosure,
                    "destination_wallet": conn.destination_wallet,
                    "destination_label": conn.destination_label,
                    "is_reserve_wallet": conn.is_reserve_wallet,
                    "path_count": conn.path_count,
                    "min_hop_distance": conn.min_hop_distance,
                    "total_taint_received": conn.total_taint_received,
                    "taint_currency": conn.taint_currency,
                    "finding_type": conn.finding_type,
                    "evidentiary_note": conn.evidentiary_note,
                }
                for conn in self.exchange_connections
            ],
            "discovered_exchange_paths": [
                {
                    "path_id": p.path_id,
                    "total_hops": p.total_hops,
                    "terminating_address": p.terminating_address,
                    "exchange_name": p.exchange_name,
                    "terminating_taint": p.terminating_taint,
                    "steps": [
                        {
                            "hop_number": s.hop_number,
                            "txid": s.txid,
                            "from_address": s.from_address,
                            "to_address": s.to_address,
                            "value": s.value,
                            "taint_ratio": s.taint_ratio,
                            "taint_amount": s.taint_amount,
                            "block_height": s.block_height,
                            "timestamp": s.timestamp,
                            "attribution_actor": s.attribution.actor if s.attribution else None,
                            "attribution_label": s.attribution.label if s.attribution else None,
                        }
                        for s in p.steps
                    ],
                }
                for p in self.paths
                if p.reached_exchange
            ][:15],
            "aml_transaction_risk_note": self.aml_transaction_risk_note,
            "disclaimer": self.disclaimer,
        }
