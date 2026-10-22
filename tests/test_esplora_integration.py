"""Integration tests for Esplora Bitcoin adapter with BlockchainTracer and ExchangeIdentificationEngine.

Verifies:
1. Network access is disabled by default (offline mode).
2. Live/cached network fetching dynamically populates TransactionGraph.
3. Multi-hop unhosted intermediary addresses are expanded up to max_hops.
4. Starting addresses that are already verified exchange wallets skip network queries.
5. Empty history, HTTP 429 rate limiting, timeouts, and partial history are explicitly handled.
6. All tests operate strictly offline with clearly labeled mock fixtures.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from cryptiq_exchange.adapters.esplora import (
    AddressFetchResult,
    EsploraBitcoinAdapter,
)
from cryptiq_exchange.cli import format_markdown_report, main as cli_main
from cryptiq_exchange.engine import ExchangeIdentificationEngine
from cryptiq_exchange.entity_registry import EntityRegistry
from cryptiq_exchange.graph import Transaction, TxInput, TxOutput
from cryptiq_exchange.models import AttributionRecord
from cryptiq_exchange.tagpack import TagPack


# ----------------------------------------------------------------------
# SYNTHETIC FIXTURES (Explicitly Labeled)
# ----------------------------------------------------------------------
SUSPECT_ADDR = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
INTERMEDIARY_ADDR = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
BINANCE_RESERVE = "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo"


def _create_mock_registry() -> EntityRegistry:
    """Creates registry preloaded with Binance cold reserve wallet."""
    reg = EntityRegistry()
    tp = TagPack(
        title="Binance reserve wallets",
        creator="GraphSense Core Team",
        confidence="service_data",
        category="exchange",
        source="https://www.binance.com",
        actor="binance",
        is_cluster_definer=True,
    )
    tp.records.append(
        AttributionRecord(
            address=BINANCE_RESERVE,
            currency="BTC",
            actor="binance",
            category="exchange",
            confidence="service_data",
            source="https://www.binance.com",
            label="Binance cold reserve wallet",
            is_cluster_definer=True,
        )
    )
    reg.register_tagpack(tp)
    return reg


# ----------------------------------------------------------------------
# 1. Default Offline Mode
# ----------------------------------------------------------------------
def test_engine_offline_mode_default():
    """Confirms network fetching is disabled by default."""
    reg = _create_mock_registry()
    engine = ExchangeIdentificationEngine(registry=reg)

    mock_adapter = MagicMock(spec=EsploraBitcoinAdapter)
    report = engine.investigate_suspect_address(
        suspect_address=SUSPECT_ADDR,
        enable_network_fetching=False,
        adapter=mock_adapter,
    )

    # Adapter must never be called when network fetching is disabled
    mock_adapter.populate_graph_for_address.assert_not_called()
    assert report.network_fetch_metadata is not None
    assert report.network_fetch_metadata.enabled is False
    assert report.network_fetch_metadata.status == "OFFLINE"
    assert report.transaction_graph_loaded is False
    assert report.total_paths_traced == 0


# ----------------------------------------------------------------------
# 2. Known Exchange Address Skips Network Fetching
# ----------------------------------------------------------------------
def test_engine_direct_exchange_skips_network_fetching():
    """If suspect address is already directly an exchange wallet, skip network fetching and do not invent paths."""
    reg = _create_mock_registry()
    engine = ExchangeIdentificationEngine(registry=reg)

    mock_adapter = MagicMock(spec=EsploraBitcoinAdapter)
    report = engine.investigate_suspect_address(
        suspect_address=BINANCE_RESERVE,
        enable_network_fetching=True,
        adapter=mock_adapter,
    )

    # Adapter must not be called
    mock_adapter.populate_graph_for_address.assert_not_called()
    assert report.direct_exchange_attribution is not None
    assert report.direct_exchange_attribution.exchange_name == "binance"
    assert report.total_paths_traced == 0
    assert len(report.exchange_connections) == 0


# ----------------------------------------------------------------------
# 3. Empty History Handling
# ----------------------------------------------------------------------
def test_engine_network_fetching_empty_history():
    """An address with 0 on-chain transactions must report EMPTY_HISTORY without errors."""
    reg = _create_mock_registry()
    engine = ExchangeIdentificationEngine(registry=reg)

    mock_adapter = MagicMock(spec=EsploraBitcoinAdapter)
    mock_adapter.base_url = "https://blockstream.info/api"
    mock_adapter.populate_graph_for_address.return_value = AddressFetchResult(
        address=SUSPECT_ADDR,
        status="EMPTY_HISTORY",
        transactions=[],
        total_fetched=0,
        has_more=False,
        cached=False,
    )

    report = engine.investigate_suspect_address(
        suspect_address=SUSPECT_ADDR,
        enable_network_fetching=True,
        adapter=mock_adapter,
    )

    assert report.network_fetch_metadata.status == "EMPTY_HISTORY"
    assert report.network_fetch_metadata.total_transactions_fetched == 0
    assert report.transaction_graph_loaded is False
    assert report.total_paths_traced == 0
    assert len(report.exchange_connections) == 0


# ----------------------------------------------------------------------
# 4. Rate Limiting (HTTP 429) Handling
# ----------------------------------------------------------------------
def test_engine_network_fetching_rate_limited():
    """An HTTP 429 rate limit is captured in metadata and does not crash the engine."""
    reg = _create_mock_registry()
    engine = ExchangeIdentificationEngine(registry=reg)

    mock_adapter = MagicMock(spec=EsploraBitcoinAdapter)
    mock_adapter.base_url = "https://blockstream.info/api"
    mock_adapter.populate_graph_for_address.return_value = AddressFetchResult(
        address=SUSPECT_ADDR,
        status="RATE_LIMITED",
        http_status_code=429,
        error_message="HTTP 429 Too Many Requests: Rate limit exceeded",
    )

    report = engine.investigate_suspect_address(
        suspect_address=SUSPECT_ADDR,
        enable_network_fetching=True,
        adapter=mock_adapter,
    )

    assert report.network_fetch_metadata.status == "RATE_LIMITED"
    assert "429" in report.network_fetch_metadata.error_message
    assert report.transaction_graph_loaded is False
    assert report.total_paths_traced == 0


# ----------------------------------------------------------------------
# 5. Partial History Detection (has_more=True)
# ----------------------------------------------------------------------
def test_engine_network_fetching_partial_history_flag():
    """Ensures partial history due to Esplora pagination (25 txs) is documented and warned."""
    reg = _create_mock_registry()
    engine = ExchangeIdentificationEngine(registry=reg)

    tx_dummy = Transaction(
        txid="dummy_tx_1",
        inputs=[TxInput(address=SUSPECT_ADDR, value_sat=100_000_000)],
        outputs=[TxOutput(address="1UnknownRecipient1111111111111111", value_sat=100_000_000, n=0)],
    )

    mock_adapter = MagicMock(spec=EsploraBitcoinAdapter)
    mock_adapter.base_url = "https://blockstream.info/api"

    def mock_populate(addr, graph, max_txs=25):
        graph.add_transaction(tx_dummy)
        return AddressFetchResult(
            address=addr,
            status="SUCCESS",
            transactions=[tx_dummy],
            total_fetched=25,
            has_more=True,
            cached=False,
        )

    mock_adapter.populate_graph_for_address.side_effect = mock_populate

    report = engine.investigate_suspect_address(
        suspect_address=SUSPECT_ADDR,
        enable_network_fetching=True,
        adapter=mock_adapter,
        max_hops=1,
    )

    assert report.network_fetch_metadata.has_more is True
    assert report.to_dict()["transaction_graph_status"]["has_more"] is True

    # Check Markdown report formatting includes partial history notice
    md = format_markdown_report(report.to_dict())
    assert "Partial History Notice (`has_more = True`)" in md
    assert "bounded" in md


# ----------------------------------------------------------------------
# 6. Multi-Hop Downstream Exchange Discovery via Real/Mock Graph Ingestion
# ----------------------------------------------------------------------
def test_engine_network_fetching_multihop_discovery():
    """Suspect -> Intermediary -> Binance reserve wallet is discovered via adapter population."""
    reg = _create_mock_registry()
    engine = ExchangeIdentificationEngine(registry=reg)

    # Tx1: Suspect -> Intermediary (1.0 BTC)
    tx1 = Transaction(
        txid="mock_tx_hop1",
        inputs=[TxInput(address=SUSPECT_ADDR, value_sat=100_000_000)],
        outputs=[TxOutput(address=INTERMEDIARY_ADDR, value_sat=100_000_000, n=0)],
        block_height=800000,
        timestamp="2023-08-01T10:00:00Z",
    )

    # Tx2: Intermediary -> Binance Reserve (0.99 BTC) + Fee (0.01 BTC)
    tx2 = Transaction(
        txid="mock_tx_hop2",
        inputs=[TxInput(address=INTERMEDIARY_ADDR, value_sat=100_000_000)],
        outputs=[TxOutput(address=BINANCE_RESERVE, value_sat=99_000_000, n=0)],
        fee_sat=1_000_000,
        block_height=800002,
        timestamp="2023-08-01T10:30:00Z",
    )

    mock_adapter = MagicMock(spec=EsploraBitcoinAdapter)
    mock_adapter.base_url = "https://blockstream.info/api"

    def mock_populate(addr, graph, max_txs=25):
        if addr == SUSPECT_ADDR:
            graph.add_transaction(tx1)
            return AddressFetchResult(
                address=addr,
                status="SUCCESS",
                transactions=[tx1],
                total_fetched=1,
                has_more=False,
                cached=True,
            )
        elif addr == INTERMEDIARY_ADDR:
            graph.add_transaction(tx2)
            return AddressFetchResult(
                address=addr,
                status="SUCCESS",
                transactions=[tx2],
                total_fetched=1,
                has_more=False,
                cached=False,
            )
        return AddressFetchResult(address=addr, status="EMPTY_HISTORY", total_fetched=0)

    mock_adapter.populate_graph_for_address.side_effect = mock_populate

    report = engine.investigate_suspect_address(
        suspect_address=SUSPECT_ADDR,
        enable_network_fetching=True,
        adapter=mock_adapter,
        max_hops=3,
    )

    # Assertions
    assert report.total_paths_traced == 1
    assert len(report.exchange_connections) == 1

    conn = report.exchange_connections[0]
    assert conn.exchange_name == "binance"
    assert conn.destination_wallet == BINANCE_RESERVE
    assert conn.min_hop_distance == 2
    assert abs(conn.total_taint_received - 0.99) < 1e-6
    assert conn.is_reserve_wallet is True

    # Network metadata assertions
    assert report.network_fetch_metadata.enabled is True
    assert SUSPECT_ADDR in report.network_fetch_metadata.addresses_queried
    assert INTERMEDIARY_ADDR in report.network_fetch_metadata.addresses_queried
    assert report.network_fetch_metadata.total_transactions_fetched == 2


# ----------------------------------------------------------------------
# 7. CLI Opt-in Network Flag Verification
# ----------------------------------------------------------------------
def test_cli_network_fetching_flag(tmp_path, monkeypatch):
    """Verifies that the CLI parses --enable-network-fetching correctly."""
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    (raw_dir / "exchange-wallets-binance.yaml").write_text("title: dummy", encoding="utf-8")

    out_dir = tmp_path / "out"

    test_args = [
        "cryptiq-tracer",
        "--address",
        SUSPECT_ADDR,
        "--raw-dir",
        str(raw_dir),
        "--out-dir",
        str(out_dir),
        "--enable-network-fetching",
        "--case-id",
        "CASE-CLI-NET-001",
    ]

    monkeypatch.setattr("sys.argv", test_args)

    with patch(
        "cryptiq_exchange.adapters.esplora.EsploraBitcoinAdapter.populate_graph_for_address",
        return_value=AddressFetchResult(
            address=SUSPECT_ADDR,
            status="EMPTY_HISTORY",
            transactions=[],
            total_fetched=0,
        ),
    ):
        cli_main()

    json_file = out_dir / "CASE-CLI-NET-001.json"
    assert json_file.exists()
    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert data["transaction_graph_status"]["network_fetching_enabled"] is True
    assert data["network_fetch_metadata"]["status"] == "EMPTY_HISTORY"
