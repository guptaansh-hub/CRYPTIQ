"""Unit and integration tests for the CRYPTIQ REST API.

Tests:
1. Health check endpoint (GET /api/v1/health).
2. Entity statistics endpoint (GET /api/v1/entities).
3. Investigation endpoint parameter validation (POST /api/v1/investigate).
4. Direct exchange wallet identification via API.
5. Offline investigation behavior by default.
6. Multi-hop flow discovery with mocked on-chain adapter responses.
7. Safe retrieval of case reports (GET /api/v1/cases/{case_id}).
8. Protection against path traversal and sensitive path exposure.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from cryptiq_exchange.adapters.esplora import AddressFetchResult
from cryptiq_exchange.api.app import create_app
from cryptiq_exchange.entity_registry import EntityRegistry
from cryptiq_exchange.graph import Transaction, TxInput, TxOutput
from cryptiq_exchange.models import AttributionRecord
from cryptiq_exchange.tagpack import TagPack


# ----------------------------------------------------------------------
# Test Fixtures & Setup
# ----------------------------------------------------------------------
BINANCE_RESERVE = "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo"
SUSPECT_ADDR = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
INTERMEDIARY_ADDR = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"


def _create_test_registry() -> EntityRegistry:
    reg = EntityRegistry()
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
        AttributionRecord(
            address=BINANCE_RESERVE,
            currency="BTC",
            actor="binance",
            category="exchange",
            confidence="service_data",
            source="https://www.binance.com",
            label="Binance cold vault",
            is_cluster_definer=True,
        )
    )
    reg.register_tagpack(tp_binance)
    return reg


@pytest.fixture
def client(tmp_path):
    reg = _create_test_registry()
    inv_dir = tmp_path / "investigations"
    inv_dir.mkdir()
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    app = create_app(
        registry=reg,
        investigations_dir=inv_dir,
        cache_dir=cache_dir,
    )
    return TestClient(app)


# ----------------------------------------------------------------------
# 1. Health & Dependency Status Tests
# ----------------------------------------------------------------------
def test_api_health_endpoint(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "CRYPTIQ Forensic Analytics Engine"
    assert data["problem_statement"] == "SIH26183"
    assert data["entities_loaded"]["tagpacks_count"] >= 1
    assert "binance" in data["entities_loaded"]["exchanges"]
    assert "disabled (offline)" in data["network_adapter"]["default_mode"]


# ----------------------------------------------------------------------
# 2. Entity Statistics Tests
# ----------------------------------------------------------------------
def test_api_entities_endpoint(client):
    response = client.get("/api/v1/entities")
    assert response.status_code == 200
    data = response.json()
    assert data["total_records"] >= 1
    assert data["by_category"].get("exchange", 0) >= 1
    assert data["by_actor"].get("binance", 0) >= 1
    assert len(data["tagpacks"]) >= 1


# ----------------------------------------------------------------------
# 3. Request Validation Tests
# ----------------------------------------------------------------------
def test_api_investigate_invalid_address(client):
    # Invalid cryptocurrency address
    payload = {
        "address": "not_a_valid_crypto_address_12345",
        "case_id": "CASE-TEST-INVALID-001",
    }
    response = client.post("/api/v1/investigate", json=payload)
    assert response.status_code == 422
    assert "failed cryptographic validation" in response.json()["detail"]


def test_api_investigate_invalid_taint_model(client):
    payload = {
        "address": SUSPECT_ADDR,
        "taint_model": "unsupported_model",
    }
    response = client.post("/api/v1/investigate", json=payload)
    assert response.status_code == 422


def test_api_investigate_invalid_max_hops(client):
    payload = {
        "address": SUSPECT_ADDR,
        "max_hops": 25,  # Exceeds maximum 10
    }
    response = client.post("/api/v1/investigate", json=payload)
    assert response.status_code == 422


# ----------------------------------------------------------------------
# 4. Direct Exchange Attribution via API
# ----------------------------------------------------------------------
def test_api_investigate_direct_exchange(client):
    payload = {
        "address": BINANCE_RESERVE,
        "case_id": "CASE-DIRECT-BINANCE-001",
    }
    response = client.post("/api/v1/investigate", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["case_id"] == "CASE-DIRECT-BINANCE-001"
    assert data["address_validation"]["is_valid"] is True
    assert data["direct_exchange_attribution"] is not None
    assert data["direct_exchange_attribution"]["exchange_name"] == "binance"
    assert data["direct_exchange_attribution"]["is_reserve_wallet"] is True
    # Zero invented paths
    assert data["total_paths_traced"] == 0
    assert len(data["exchange_connections"]) == 0


# ----------------------------------------------------------------------
# 5. Default Offline Investigation (No Network)
# ----------------------------------------------------------------------
def test_api_investigate_offline_default(client):
    payload = {
        "address": SUSPECT_ADDR,
        "case_id": "CASE-OFFLINE-001",
    }
    response = client.post("/api/v1/investigate", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["transaction_graph_status"]["network_fetching_enabled"] is False
    assert data["network_fetch_metadata"]["enabled"] is False
    assert data["network_fetch_metadata"]["status"] == "OFFLINE"
    assert data["transaction_graph_status"]["graph_loaded"] is False
    assert data["total_paths_traced"] == 0


# ----------------------------------------------------------------------
# 6. Multi-Hop Tracing via Mocked Adapter Ingestion
# ----------------------------------------------------------------------
def test_api_investigate_multihop_mocked_network(client):
    tx1 = Transaction(
        txid="tx_api_hop1",
        inputs=[TxInput(address=SUSPECT_ADDR, value_sat=100_000_000)],
        outputs=[TxOutput(address=INTERMEDIARY_ADDR, value_sat=100_000_000, n=0)],
    )
    tx2 = Transaction(
        txid="tx_api_hop2",
        inputs=[TxInput(address=INTERMEDIARY_ADDR, value_sat=100_000_000)],
        outputs=[TxOutput(address=BINANCE_RESERVE, value_sat=99_000_000, n=0)],
        fee_sat=1_000_000,
    )

    def mock_populate(addr, graph, max_txs=25):
        if addr == SUSPECT_ADDR:
            graph.add_transaction(tx1)
            return AddressFetchResult(
                address=addr,
                status="SUCCESS",
                transactions=[tx1],
                total_fetched=1,
                has_more=False,
            )
        elif addr == INTERMEDIARY_ADDR:
            graph.add_transaction(tx2)
            return AddressFetchResult(
                address=addr,
                status="SUCCESS",
                transactions=[tx2],
                total_fetched=1,
                has_more=False,
            )
        return AddressFetchResult(address=addr, status="EMPTY_HISTORY", total_fetched=0)

    with patch(
        "cryptiq_exchange.adapters.esplora.EsploraBitcoinAdapter.populate_graph_for_address",
        side_effect=mock_populate,
    ):
        payload = {
            "address": SUSPECT_ADDR,
            "case_id": "CASE-API-MULTIHOP-001",
            "enable_network_fetching": True,
            "max_hops": 3,
        }
        response = client.post("/api/v1/investigate", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["transaction_graph_status"]["network_fetching_enabled"] is True
        assert data["total_paths_traced"] == 1
        assert len(data["exchange_connections"]) == 1

        conn = data["exchange_connections"][0]
        assert conn["exchange_name"] == "binance"
        assert conn["destination_wallet"] == BINANCE_RESERVE
        assert conn["min_hop_distance"] == 2
        assert abs(conn["total_taint_received"] - 0.99) < 1e-6


# ----------------------------------------------------------------------
# 7. Safe Case Retrieval & Path Traversal Prevention
# ----------------------------------------------------------------------
def test_api_get_saved_case_report(client):
    # First, run an investigation to generate a case file
    payload = {
        "address": BINANCE_RESERVE,
        "case_id": "CASE-RETRIEVAL-001",
    }
    create_resp = client.post("/api/v1/investigate", json=payload)
    assert create_resp.status_code == 200

    # Retrieve case report
    get_resp = client.get("/api/v1/cases/CASE-RETRIEVAL-001")
    assert get_resp.status_code == 200
    retrieved = get_resp.json()
    assert retrieved["case_id"] == "CASE-RETRIEVAL-001"
    assert retrieved["suspect_address"] == BINANCE_RESERVE


def test_api_get_nonexistent_case_report(client):
    response = client.get("/api/v1/cases/CASE-DOES-NOT-EXIST-999")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_api_path_traversal_prevention(client):
    # Malicious case IDs with directory traversal attempts
    bad_case_ids = [
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "case/with/slashes",
        "case;rm -rf",
    ]
    for bad_id in bad_case_ids:
        response = client.get(f"/api/v1/cases/{bad_id}")
        # Must be rejected as Bad Request (400) or Not Found/Unprocessable, never return 500 or file content
        assert response.status_code in (400, 404)
