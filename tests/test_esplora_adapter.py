"""Unit tests for the read-only Esplora Bitcoin REST API adapter.

Includes offline tests with synthetic fixtures and opt-in live network integration tests.
All synthetic fixtures are explicitly labeled.
"""

import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error

import pytest

from cryptiq_exchange.adapters.esplora import (
    AddressFetchResult,
    EsploraBitcoinAdapter,
)
from cryptiq_exchange.graph import TransactionGraph

# ======================================================================
# SYNTHETIC OFFLINE FIXTURE FOR UNIT TESTING (Explicitly Labeled)
# ======================================================================
MOCK_SYNTHETIC_ESPLORA_PAYLOAD = {
    "txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
    "version": 1,
    "locktime": 0,
    "vin": [
        {
            "txid": "0000000000000000000000000000000000000000000000000000000000000000",
            "vout": 0,
            "prevout": {
                "scriptpubkey": "76a914111111111111111111111111111111111111111188ac",
                "scriptpubkey_asm": "OP_DUP OP_HASH160 ... OP_EQUALVERIFY OP_CHECKSIG",
                "scriptpubkey_type": "p2pkh",
                "scriptpubkey_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                "value": 50000000,  # 0.5 BTC in satoshis
            },
            "scriptsig": "483045...",
            "sequence": 4294967295,
            "is_coinbase": False,
        }
    ],
    "vout": [
        {
            "scriptpubkey": "a914...",
            "scriptpubkey_type": "p2sh",
            "scriptpubkey_address": "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo",  # Binance cold wallet
            "value": 49995000,  # 0.49995 BTC in satoshis
        },
        {
            "scriptpubkey": "6a04...",
            "scriptpubkey_type": "op_return",
            "value": 0,
        },
    ],
    "size": 225,
    "weight": 900,
    "fee": 5000,  # 0.00005 BTC in satoshis
    "status": {
        "confirmed": True,
        "block_height": 800000,
        "block_hash": "0000000000000000000123456789abcdef",
        "block_time": 1690000000,
    },
}

MOCK_COINBASE_PAYLOAD = {
    "txid": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "version": 1,
    "vin": [
        {
            "is_coinbase": True,
            "sequence": 4294967295,
        }
    ],
    "vout": [
        {
            "scriptpubkey_type": "p2pkh",
            "scriptpubkey_address": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "value": 625000000,  # 6.25 BTC
        }
    ],
    "fee": 0,
    "status": {
        "confirmed": True,
        "block_height": 700000,
        "block_time": 1650000000,
    },
}


# ----------------------------------------------------------------------
# 1. Schema Parsing & Satoshi Accounting Tests
# ----------------------------------------------------------------------
def test_parse_transaction_satoshi_accounting(tmp_path):
    adapter = EsploraBitcoinAdapter(cache_dir=tmp_path)
    tx = adapter.parse_transaction_payload(
        MOCK_SYNTHETIC_ESPLORA_PAYLOAD,
        retrieval_status="TEST_PARSED",
        provenance_url="https://blockstream.info/api/tx/mock_id",
    )

    # Invariants
    assert tx.txid == "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    assert tx.confirmed is True
    assert tx.block_height == 800000
    assert tx.timestamp is not None
    assert "2023" in tx.timestamp  # block_time 1690000000 is July 2023

    # Exact integer satoshi accounting
    assert tx.fee_sat == 5000
    assert tx.fee == 0.00005  # 5000 / 1e8

    # Inputs
    assert len(tx.inputs) == 1
    inp = tx.inputs[0]
    assert inp.address == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert inp.value_sat == 50000000
    assert inp.value == 0.5
    assert inp.is_coinbase is False

    # Outputs
    assert len(tx.outputs) == 2
    out1 = tx.outputs[0]
    assert out1.address == "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo"
    assert out1.value_sat == 49995000
    assert out1.value == 0.49995
    assert out1.is_op_return is False

    # OP_RETURN output (safeguard: non-standard output is not given an invented address)
    out2 = tx.outputs[1]
    assert out2.address == "OP_RETURN"
    assert out2.value_sat == 0
    assert out2.is_op_return is True

    # Total accounting conservation (Inputs == Outputs + Fee)
    assert tx.total_input_sat == tx.total_output_sat + tx.fee_sat
    assert tx.total_input_sat == 50000000


def test_parse_coinbase_transaction_no_invented_address(tmp_path):
    adapter = EsploraBitcoinAdapter(cache_dir=tmp_path)
    tx = adapter.parse_transaction_payload(MOCK_COINBASE_PAYLOAD)

    assert len(tx.inputs) == 1
    cb_inp = tx.inputs[0]
    assert cb_inp.is_coinbase is True
    assert cb_inp.address == "COINBASE"  # Safeguard: no invented address
    assert cb_inp.value_sat == 0
    assert cb_inp.prev_txid is None


# ----------------------------------------------------------------------
# 2. Caching Separation (Confirmed Tx vs. Mutable Address History)
# ----------------------------------------------------------------------
def test_caching_separation(tmp_path):
    adapter = EsploraBitcoinAdapter(
        cache_dir=tmp_path,
        address_cache_ttl_seconds=60.0,
    )
    test_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

    # Mock network call for address transactions
    with patch.object(
        adapter, "_http_get_json", return_value=([MOCK_SYNTHETIC_ESPLORA_PAYLOAD], 200, None)
    ) as mock_get:
        res1 = adapter.fetch_address_transactions(test_addr)
        assert res1.status == "SUCCESS"
        assert res1.cached is False
        assert len(res1.transactions) == 1
        assert mock_get.call_count == 1

        # Confirmed transaction was written to permanent tx cache
        tx_cache_file = tmp_path / "transactions" / f"{MOCK_SYNTHETIC_ESPLORA_PAYLOAD['txid']}.json"
        assert tx_cache_file.exists()

        # Address history was written to address cache
        addr_cache_file = tmp_path / "addresses" / f"{test_addr}.json"
        assert addr_cache_file.exists()

        # Second call within TTL reads from address cache without network call
        res2 = adapter.fetch_address_transactions(test_addr)
        assert res2.status == "CACHED"
        assert res2.cached is True
        assert len(res2.transactions) == 1
        assert mock_get.call_count == 1  # Network was NOT called again


def test_transaction_permanent_cache(tmp_path):
    adapter = EsploraBitcoinAdapter(cache_dir=tmp_path)
    txid = MOCK_SYNTHETIC_ESPLORA_PAYLOAD["txid"]

    # Pre-populate permanent tx cache
    tx_cache_dir = tmp_path / "transactions"
    tx_cache_dir.mkdir(parents=True, exist_ok=True)
    (tx_cache_dir / f"{txid}.json").write_text(
        json.dumps(MOCK_SYNTHETIC_ESPLORA_PAYLOAD), encoding="utf-8"
    )

    # get_transaction should read from disk cache without network call
    with patch.object(adapter, "_http_get_json") as mock_get:
        tx, status = adapter.get_transaction(txid)
        assert status == "CACHED"
        assert tx is not None
        assert tx.txid == txid
        assert mock_get.call_count == 0


# ----------------------------------------------------------------------
# 3. Error Handling & Incomplete History Tests
# ----------------------------------------------------------------------
def test_distinguish_empty_history(tmp_path):
    adapter = EsploraBitcoinAdapter(cache_dir=tmp_path)
    with patch.object(adapter, "_http_get_json", return_value=([], 200, None)):
        res = adapter.fetch_address_transactions("1EmptyAddress111111111111111111111")
        assert res.status == "EMPTY_HISTORY"
        assert len(res.transactions) == 0
        assert res.error_message is None


def test_rate_limit_handling_and_status(tmp_path):
    adapter = EsploraBitcoinAdapter(cache_dir=tmp_path, max_retries=2, min_request_interval=0.01)
    with patch.object(
        adapter,
        "_http_get_json",
        return_value=(None, 429, "HTTP 429 Too Many Requests: Rate limit exceeded"),
    ):
        res = adapter.fetch_address_transactions("1TestAddr1111111111111111111111111")
        assert res.status == "RATE_LIMITED"
        assert res.http_status_code == 429
        assert "429" in res.error_message


def test_timeout_handling_and_status(tmp_path):
    adapter = EsploraBitcoinAdapter(cache_dir=tmp_path)
    with patch.object(
        adapter,
        "_http_get_json",
        return_value=(None, 408, "Request timed out after 10.0s"),
    ):
        res = adapter.fetch_address_transactions("1TestAddr1111111111111111111111111")
        assert res.status == "TIMEOUT"
        assert res.http_status_code == 408


# ----------------------------------------------------------------------
# 4. Graph Population Integration
# ----------------------------------------------------------------------
def test_populate_graph_for_address(tmp_path):
    adapter = EsploraBitcoinAdapter(cache_dir=tmp_path)
    graph = TransactionGraph()

    with patch.object(
        adapter, "_http_get_json", return_value=([MOCK_SYNTHETIC_ESPLORA_PAYLOAD], 200, None)
    ):
        res = adapter.populate_graph_for_address(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", graph
        )
        assert res.status == "SUCCESS"
        assert len(graph.transactions) == 1

        # Check that forward transaction lookup works
        forward = graph.get_forward_transactions("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert len(forward) == 1
        assert forward[0].txid == MOCK_SYNTHETIC_ESPLORA_PAYLOAD["txid"]

        # Check receiving index
        receiving = graph.get_receiving_transactions("34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo")
        assert len(receiving) == 1


# ----------------------------------------------------------------------
# 5. Opt-in Live Network Integration Test (Skipped Offline by Default)
# ----------------------------------------------------------------------
@pytest.mark.network
@pytest.mark.skipif(
    os.environ.get("CRYPTIQ_LIVE_TEST") != "1",
    reason="Live network test skipped by default. Set CRYPTIQ_LIVE_TEST=1 to enable.",
)
def test_live_network_satoshi_genesis_tx(tmp_path):
    """OPT-IN LIVE TEST: Queries historical Block 170 transaction (Satoshi -> Hal Finney)."""
    adapter = EsploraBitcoinAdapter(cache_dir=tmp_path)
    hal_finney_txid = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"

    tx, status = adapter.get_transaction(hal_finney_txid)
    assert status == "FETCHED_OK"
    assert tx is not None
    assert tx.txid == hal_finney_txid
    assert tx.confirmed is True
    assert tx.block_height == 170
    assert tx.total_output_value == 50.0  # 50 BTC transfer
