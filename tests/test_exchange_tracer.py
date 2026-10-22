"""Comprehensive unit and integration tests for the cryptiq_exchange package."""

from pathlib import Path
import pytest

from cryptiq_exchange.address import (
    validate_address,
    canonicalize_address,
    is_valid_btc_base58,
    is_valid_btc_bech32,
    is_valid_eth_address,
)
from cryptiq_exchange.tagpack import TagPackParser, TagPack
from cryptiq_exchange.entity_registry import EntityRegistry
from cryptiq_exchange.graph import TransactionGraph, Transaction, TxInput, TxOutput
from cryptiq_exchange.taint import calculate_haircut_taint, calculate_fifo_taint
from cryptiq_exchange.tracer import BlockchainTracer
from cryptiq_exchange.engine import ExchangeIdentificationEngine

RAW_DIR = Path("D:/cryptiq-data/cryptiq-data/data/raw")


# ----------------------------------------------------------------------
# 1. Address Validation & Canonicalization Tests
# ----------------------------------------------------------------------
def test_address_validation_btc_base58():
    # Binance cold wallet (P2SH, starts with 3)
    binance_p2sh = "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo"
    info = validate_address(binance_p2sh)
    assert info.is_valid is True
    assert info.network == "BTC"
    assert info.address_format == "p2sh"
    assert info.canonical_address == binance_p2sh

    # P2PKH (starts with 1)
    p2pkh = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    info2 = validate_address(p2pkh)
    assert info2.is_valid is True
    assert info2.network == "BTC"
    assert info2.address_format == "p2pkh"


def test_address_validation_btc_bech32():
    # Bybit reserve wallet (Native SegWit, starts with bc1q)
    bybit_segwit = "bc1q2qqqt87kh33s0er58akh7v9cwjgd83z5smh9rp"
    info = validate_address(bybit_segwit)
    assert info.is_valid is True
    assert info.network == "BTC"
    assert info.address_format == "bech32_segwit"
    assert info.canonical_address == bybit_segwit.lower()

    # Uppercase SegWit canonicalizes to lowercase
    info_upper = validate_address(bybit_segwit.upper())
    assert info_upper.is_valid is True
    assert info_upper.canonical_address == bybit_segwit.lower()


def test_address_validation_ethereum():
    # EtherScamDB phishing address
    eth_addr = "0xD0cC2B24980CBCCA47EF755Da88B220a82291407"
    info = validate_address(eth_addr)
    assert info.is_valid is True
    assert info.network == "ETH"
    assert info.address_format == "eth_hex"
    assert info.canonical_address == eth_addr.lower()


def test_address_validation_invalid():
    # Arbitrary strings, malformed lengths, non-hex
    invalid_cases = [
        "",
        "   ",
        "not_an_address",
        "0x123",
        "34xp4vRoCGJym3xR7yCVPFHoCNxv4TwseINVALID",
        "bc1invalidchecksum!!!",
    ]
    for case in invalid_cases:
        info = validate_address(case)
        assert info.is_valid is False
        assert info.address_format == "invalid"


# ----------------------------------------------------------------------
# 2. TagPack Parsing & Provenance Inspection Tests
# ----------------------------------------------------------------------
def test_tagpack_binance_parsing_and_provenance():
    binance_file = RAW_DIR / "exchange-wallets-binance.yaml"
    if not binance_file.exists():
        pytest.skip("Binance tagpack file not found in data/raw")

    tp = TagPackParser.parse_file(binance_file)
    assert tp.actor == "binance"
    assert tp.category == "exchange"
    assert tp.confidence == "service_data"  # Official self-disclosure
    assert "binance.com" in tp.source
    assert tp.is_cluster_definer is True
    assert len(tp.records) >= 80

    # Ensure known cold wallet is present
    cold_wallet = "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo"
    addrs = {r.address for r in tp.records}
    assert cold_wallet in addrs


def test_tagpack_bybit_parsing_and_provenance():
    bybit_file = RAW_DIR / "exchange-wallets-bybit.yaml"
    if not bybit_file.exists():
        pytest.skip("Bybit tagpack file not found in data/raw")

    tp = TagPackParser.parse_file(bybit_file)
    assert tp.actor == "bybit"
    assert tp.category == "exchange"
    assert tp.confidence == "service_data"
    assert "bybit.com" in tp.source
    assert len(tp.records) >= 8

    bybit_btc = "bc1q2qqqt87kh33s0er58akh7v9cwjgd83z5smh9rp"
    addrs = {r.address for r in tp.records}
    assert bybit_btc in addrs


def test_tagpack_etherscamdb_parsing():
    scam_file = RAW_DIR / "etherscamdb_tagpack.yaml"
    if not scam_file.exists():
        pytest.skip("EtherScamDB tagpack file not found in data/raw")

    tp = TagPackParser.parse_file(scam_file)
    assert tp.title == "Ethereum Scam Database TagPack"
    assert len(tp.records) >= 3000

    known_scam = "0xd0cc2b24980cbcca47ef755da88b220a82291407"
    addrs = {r.address for r in tp.records}
    assert known_scam in addrs


# ----------------------------------------------------------------------
# 3. Entity Registry Lookup & Uninvented Safeguard Tests
# ----------------------------------------------------------------------
def test_entity_registry_lookups():
    reg = EntityRegistry()
    if (RAW_DIR / "exchange-wallets-binance.yaml").exists():
        reg.load_tagpack_file(RAW_DIR / "exchange-wallets-binance.yaml")
    if (RAW_DIR / "exchange-wallets-bybit.yaml").exists():
        reg.load_tagpack_file(RAW_DIR / "exchange-wallets-bybit.yaml")

    # 1. Match Binance
    rec_binance = reg.lookup("34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo", "BTC")
    assert rec_binance is not None
    assert rec_binance.actor == "binance"
    assert rec_binance.category == "exchange"
    assert rec_binance.confidence == "service_data"

    # 2. Match Bybit
    rec_bybit = reg.lookup("bc1q2qqqt87kh33s0er58akh7v9cwjgd83z5smh9rp", "BTC")
    assert rec_bybit is not None
    assert rec_bybit.actor == "bybit"
    assert rec_bybit.category == "exchange"

    # 3. Unverified address MUST return None (no invented labels)
    unverified = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert reg.lookup(unverified) is None
    assert reg.is_exchange(unverified) is False


# ----------------------------------------------------------------------
# 4. Taint Calculation Mathematics Tests
# ----------------------------------------------------------------------
def test_haircut_taint_conservation():
    # Transaction: 2 inputs (1.0 tainted from addrA, 1.0 clean from addrB) -> 2.0 total in
    # 2 outputs: out1 = 1.5, out2 = 0.5
    tx = Transaction(
        txid="tx_test_1",
        inputs=[
            TxInput(address="addrA", value=1.0),
            TxInput(address="addrB", value=1.0),
        ],
        outputs=[
            TxOutput(address="addrOut1", value=1.5, n=0),
            TxOutput(address="addrOut2", value=0.5, n=1),
        ],
    )
    # addrA has 100% taint (1.0). Total in = 2.0, so blended taint ratio = 1.0 / 2.0 = 0.5
    taint_dict = calculate_haircut_taint(tx, spending_address="addrA", incoming_taint_ratio=1.0)

    ratio1, amount1 = taint_dict["addrOut1"]
    ratio2, amount2 = taint_dict["addrOut2"]

    assert ratio1 == 0.5
    assert amount1 == 0.75  # 1.5 * 0.5
    assert ratio2 == 0.5
    assert amount2 == 0.25  # 0.5 * 0.5

    # Conservation of taint: total output taint (0.75 + 0.25 = 1.0) == input taint (1.0)
    assert abs((amount1 + amount2) - 1.0) < 1e-9


def test_fifo_taint_sequential_exhaustion():
    # Total input: 1.0 tainted from addrA.
    # Output 1: 0.6
    # Output 2: 0.4
    tx = Transaction(
        txid="tx_test_2",
        inputs=[TxInput(address="addrA", value=1.0)],
        outputs=[
            TxOutput(address="addrOut1", value=0.6, n=0),
            TxOutput(address="addrOut2", value=0.4, n=1),
        ],
    )
    # Incoming taint = 0.7 BTC
    taint_dict = calculate_fifo_taint(tx, spending_address="addrA", incoming_taint_ratio=0.7)

    ratio1, amount1 = taint_dict["addrOut1"]
    ratio2, amount2 = taint_dict["addrOut2"]

    # FIFO satisfies Output 1 first (0.6 fully tainted), remaining 0.1 goes to Output 2
    assert amount1 == 0.6
    assert ratio1 == 1.0
    assert abs(amount2 - 0.1) < 1e-9
    assert abs(ratio2 - (0.1 / 0.4)) < 1e-9
    assert abs((amount1 + amount2) - 0.7) < 1e-9


# ----------------------------------------------------------------------
# 5. Multi-Hop Tracing & Case Engine Integration Tests
# ----------------------------------------------------------------------
def test_engine_end_to_end_investigation():
    # Setup mock registry with 1 verified exchange wallet and 1 scam address
    reg = EntityRegistry()
    binance_wallet = "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo"
    tp_binance = TagPack(
        title="Binance reserve wallets",
        creator="GraphSense Core Team",
        confidence="service_data",
        category="exchange",
        source="https://www.binance.com",
        actor="binance",
        is_cluster_definer=True,
    )
    tp_binance.records.append(
        from_models_attribution(binance_wallet, "binance", "exchange", "service_data")
    )
    reg.register_tagpack(tp_binance)

    # Setup 2-hop transaction graph with valid Bitcoin addresses:
    # Suspect (1A1z...) -> tx1 -> Intermediary1 (1BvB...) -> tx2 -> Binance Reserve Wallet (34xp...)
    graph = TransactionGraph()
    suspect_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    intermediary = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"

    graph.add_transfer(
        from_address=suspect_addr,
        to_address=intermediary,
        value=2.0,
        txid="tx_hop_1",
        block_height=800000,
    )
    graph.add_transfer(
        from_address=intermediary,
        to_address=binance_wallet,
        value=1.99,
        txid="tx_hop_2",
        fee=0.01,
        block_height=800002,
    )

    engine = ExchangeIdentificationEngine(registry=reg, graph=graph)
    report = engine.investigate_suspect_address(
        suspect_address=suspect_addr,
        max_hops=3,
        currency_hint="BTC",
    )

    # Verify report structure & findings
    assert report.total_paths_traced == 1
    assert len(report.exchange_connections) == 1

    conn = report.exchange_connections[0]
    assert conn.exchange_name == "binance"
    assert conn.min_hop_distance == 2
    assert conn.destination_wallet == binance_wallet
    assert conn.attribution_confidence == "service_data"
    assert conn.is_reserve_wallet is True
    assert conn.finding_type == "TRANSACTION_CONNECTION_ESTABLISHED"

    # Verify evidentiary boundaries in report
    assert "does NOT prove that the exchange entity itself is fraudulent" in conn.evidentiary_note
    assert "Offline Elliptic Random Forest model requires the full 165 graph/local feature vector" in report.aml_transaction_risk_note


def test_engine_invalid_address_rejection():
    engine = ExchangeIdentificationEngine()
    report = engine.investigate_suspect_address("invalid_address_123")
    assert report.address_validation.is_valid is False
    assert report.total_paths_traced == 0
    assert len(report.exchange_connections) == 0


def test_cli_resolve_raw_dir(tmp_path):
    from cryptiq_exchange.cli import resolve_raw_dir
    valid_raw = tmp_path / "raw"
    valid_raw.mkdir()
    (valid_raw / "exchange-wallets-binance.yaml").write_text("title: dummy", encoding="utf-8")

    assert resolve_raw_dir(valid_raw) == valid_raw

    with pytest.raises(FileNotFoundError):
        resolve_raw_dir(tmp_path / "nonexistent")


def test_cli_format_markdown_report():
    from cryptiq_exchange.cli import format_markdown_report
    dummy_dict = {
        "case_id": "CASE-TEST-001",
        "suspect_address": "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo",
        "currency": "BTC",
        "created_at_utc": "2026-10-18T12:00:00Z",
        "address_validation": {
            "canonical": "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo",
            "format": "p2sh",
            "is_valid": True,
        },
        "direct_exchange_attribution": {
            "exchange_name": "binance",
            "attribution_confidence": "service_data",
            "source_disclosure": "https://binance.com",
            "label": "binance reserve wallets BTC",
            "is_reserve_wallet": True,
            "currency": "BTC",
            "finding_type": "DIRECT_EXCHANGE_WALLET_IDENTIFIED",
            "evidentiary_note": "Direct attribution note.",
        },
        "suspect_prior_abuse_flags": [],
        "transaction_graph_status": {
            "transactions_indexed": 0,
            "graph_loaded": False,
        },
        "total_paths_traced": 0,
        "exchange_connections": [],
        "aml_transaction_risk_note": "Offline model boundary note.",
        "disclaimer": "Verified external disclosures only.",
    }
    md = format_markdown_report(dummy_dict)
    assert "CASE-TEST-001" in md
    assert "BINANCE" in md
    assert "service_data" in md
    assert "DIRECT_EXCHANGE_WALLET_IDENTIFIED" in md


# ----------------------------------------------------------------------
# 6. Explicit 4 Scenario Tests (Exchange, Scam, Unknown, Multi-Hop)
# ----------------------------------------------------------------------
def test_scenario_1_known_exchange_address():
    """Scenario 1: Known exchange address (Binance Proof-of-Reserves cold wallet).
    Must report direct attribution separately; must NOT classify as an abuse flag;
    must NOT invent a transaction path.
    """
    reg = EntityRegistry()
    reg.load_known_raw_tagpacks(RAW_DIR)

    engine = ExchangeIdentificationEngine(registry=reg)
    binance_cold_wallet = "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo"

    report = engine.investigate_suspect_address(binance_cold_wallet)

    assert report.address_validation.is_valid is True
    # 1. Direct exchange attribution is detected
    assert report.direct_exchange_attribution is not None
    assert report.direct_exchange_attribution.exchange_name == "binance"
    assert report.direct_exchange_attribution.attribution_confidence == "service_data"
    assert report.direct_exchange_attribution.is_reserve_wallet is True

    # 2. ZERO abuse flags (reserve disclosure must NOT be counted as abuse!)
    assert len(report.suspect_address_prior_flags) == 0

    # 3. ZERO invented transaction paths / connections
    assert report.total_paths_traced == 0
    assert len(report.exchange_connections) == 0


def test_scenario_2_known_scam_address():
    """Scenario 2: Known scam address (from EtherScamDB).
    Must report scam abuse flag; must NOT report exchange attribution.
    """
    reg = EntityRegistry()
    reg.load_known_raw_tagpacks(RAW_DIR)

    engine = ExchangeIdentificationEngine(registry=reg)
    scam_address = "0xD0cC2B24980CBCCA47EF755Da88B220a82291407"

    report = engine.investigate_suspect_address(scam_address)

    assert report.address_validation.is_valid is True
    # 1. NOT an exchange
    assert report.direct_exchange_attribution is None

    # 2. Correctly flags abuse
    assert len(report.suspect_address_prior_flags) >= 1
    flag = report.suspect_address_prior_flags[0]
    assert flag.abuse == "phishing"
    assert flag.label == "myelherwallel.com"
    assert "cryptoscamdb.org" in flag.source

    # 3. No invented exchange connections
    assert len(report.exchange_connections) == 0


def test_scenario_3_unknown_address():
    """Scenario 3: Unknown valid address not in any tagpack.
    Must validate cryptographically; must have zero abuse flags; zero exchange connections.
    """
    reg = EntityRegistry()
    reg.load_known_raw_tagpacks(RAW_DIR)

    engine = ExchangeIdentificationEngine(registry=reg)
    unknown_valid_btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

    report = engine.investigate_suspect_address(unknown_valid_btc)

    assert report.address_validation.is_valid is True
    assert report.direct_exchange_attribution is None
    assert len(report.suspect_address_prior_flags) == 0
    assert report.total_paths_traced == 0
    assert len(report.exchange_connections) == 0


def test_scenario_4_multihop_transaction_path():
    """Scenario 4: Multi-hop transaction path to an exchange.
    Suspect (unknown) -> tx1 -> Mule -> tx2 -> Binance Reserve.
    Must trace 2 hops, compute taint, and report downstream connection separately
    from direct attribution.
    """
    reg = EntityRegistry()
    reg.load_known_raw_tagpacks(RAW_DIR)

    suspect_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    mule_addr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    binance_wallet = "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo"

    graph = TransactionGraph()
    graph.add_transfer(
        from_address=suspect_addr,
        to_address=mule_addr,
        value=3.0,
        txid="tx_steal_funds",
        block_height=800100,
    )
    graph.add_transfer(
        from_address=mule_addr,
        to_address=binance_wallet,
        value=2.99,
        fee=0.01,
        txid="tx_deposit_to_binance",
        block_height=800105,
    )

    engine = ExchangeIdentificationEngine(registry=reg, graph=graph)
    report = engine.investigate_suspect_address(suspect_addr, max_hops=3)

    assert report.address_validation.is_valid is True
    # 1. Suspect address itself is NOT Binance
    assert report.direct_exchange_attribution is None
    assert len(report.suspect_address_prior_flags) == 0

    # 2. Graph loaded and traced
    assert report.transaction_graph_loaded is True
    assert report.total_paths_traced == 1

    # 3. Downstream exchange connection identified
    assert len(report.exchange_connections) == 1
    conn = report.exchange_connections[0]
    assert conn.exchange_name == "binance"
    assert conn.min_hop_distance == 2
    assert conn.destination_wallet == binance_wallet
    assert conn.is_reserve_wallet is True
    assert conn.attribution_confidence == "service_data"
    assert conn.finding_type == "TRANSACTION_CONNECTION_ESTABLISHED"
    assert abs(conn.total_taint_received - 2.99) < 1e-6


def from_models_attribution(addr, actor, category, confidence):
    from cryptiq_exchange.models import AttributionRecord
    return AttributionRecord(
        address=addr,
        currency="BTC",
        actor=actor,
        category=category,
        confidence=confidence,
        source="https://test.provenance.org",
        label=f"{actor} test wallet",
        is_cluster_definer=True,
    )
