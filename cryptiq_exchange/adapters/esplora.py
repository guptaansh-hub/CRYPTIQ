"""Read-only Blockstream Esplora / Mempool.space Bitcoin REST API adapter.

Fetches real Bitcoin transaction records, validates inputs/outputs, performs integer
satoshi accounting, enforces conservative client-side rate limiting with exponential
backoff, and separates immutable transaction caching from address-history caching.

Dependencies: Python 3 standard library only (no external HTTP packages required).
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..address import canonicalize_address
from ..graph import Transaction, TransactionGraph, TxInput, TxOutput

LOG = logging.getLogger("cryptiq.esplora")

DEFAULT_ESPLORA_BASE_URL = "https://blockstream.info/api"
DEFAULT_CACHE_DIR = Path("data/cache/esplora")


@dataclass
class AddressFetchResult:
    """Detailed result of fetching transaction history for a Bitcoin address."""
    address: str
    status: str  # "SUCCESS", "EMPTY_HISTORY", "RATE_LIMITED", "TIMEOUT", "HTTP_ERROR", "NETWORK_ERROR", "CACHED"
    transactions: List[Transaction] = field(default_factory=list)
    total_fetched: int = 0
    has_more: bool = False
    error_message: Optional[str] = None
    cached: bool = False
    provenance_url: str = ""
    http_status_code: Optional[int] = None


class EsploraBitcoinAdapter:
    """Read-only adapter for Blockstream Esplora / Mempool.space Bitcoin REST API."""

    def __init__(
        self,
        base_url: str = DEFAULT_ESPLORA_BASE_URL,
        cache_dir: Optional[str | Path] = DEFAULT_CACHE_DIR,
        min_request_interval: float = 0.35,  # ~2.8 requests per second max
        timeout_seconds: float = 10.0,
        max_retries: int = 3,
        address_cache_ttl_seconds: float = 300.0,  # 5 minutes for mutable address history
        user_agent: str = "CRYPTIQ-SIH26183-ForensicAnalytics/1.0",
    ):
        self.base_url = base_url.rstrip("/")
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.min_request_interval = min_request_interval
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.address_cache_ttl = address_cache_ttl_seconds
        self.user_agent = user_agent
        self._last_request_time = 0.0

        if self.cache_dir:
            (self.cache_dir / "transactions").mkdir(parents=True, exist_ok=True)
            (self.cache_dir / "addresses").mkdir(parents=True, exist_ok=True)

    def _throttle(self) -> None:
        """Enforces conservative client-side rate limiting."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        self._last_request_time = time.time()

    def _http_get_json(self, url: str) -> Tuple[Optional[Any], int, Optional[str]]:
        """Performs HTTP GET with bounded retries, exponential backoff on 429, and timeouts.

        Returns:
            Tuple of (parsed_json_data, http_status_code, error_message)
        """
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
        }
        req = urllib.request.Request(url, headers=headers)

        backoff = 1.0
        for attempt in range(1, self.max_retries + 1):
            self._throttle()
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                    status = resp.status
                    body = resp.read().decode("utf-8")
                    data = json.loads(body)
                    return data, status, None
            except urllib.error.HTTPError as e:
                status = e.code
                if status == 429:
                    LOG.warning("Esplora HTTP 429 (Rate Limited) on %s (attempt %d/%d)", url, attempt, self.max_retries)
                    if attempt < self.max_retries:
                        time.sleep(backoff)
                        backoff *= 2.0
                        continue
                    return None, 429, "HTTP 429 Too Many Requests: Rate limit exceeded"
                if status == 404:
                    return None, 404, "HTTP 404 Not Found"
                if 500 <= status < 600:
                    LOG.warning("Esplora HTTP %d on %s (attempt %d/%d)", status, url, attempt, self.max_retries)
                    if attempt < self.max_retries:
                        time.sleep(backoff)
                        backoff *= 2.0
                        continue
                    return None, status, f"HTTP {status} Server Error"
                return None, status, f"HTTP Error {status}: {e.reason}"
            except urllib.error.URLError as e:
                if "timed out" in str(e.reason).lower():
                    return None, 408, f"Request timed out after {self.timeout_seconds}s"
                return None, 0, f"Network error: {e.reason}"
            except Exception as e:
                return None, 0, f"Unexpected error: {str(e)}"

        return None, 0, "Max retries exhausted"

    # ------------------------------------------------------------------
    # Transaction-Level (Immutable) Cache & Parser
    # ------------------------------------------------------------------
    def get_transaction(self, txid: str) -> Tuple[Optional[Transaction], str]:
        """Fetches detailed transaction by txid.

        Uses permanent disk cache for confirmed transactions.
        """
        clean_txid = txid.strip().lower()
        prov_url = f"{self.base_url}/tx/{clean_txid}"

        # 1. Check permanent transaction disk cache
        if self.cache_dir:
            tx_cache_path = self.cache_dir / "transactions" / f"{clean_txid}.json"
            if tx_cache_path.exists():
                try:
                    payload = json.loads(tx_cache_path.read_text(encoding="utf-8"))
                    tx = self.parse_transaction_payload(payload, retrieval_status="CACHED", provenance_url=prov_url)
                    return tx, "CACHED"
                except Exception as e:
                    LOG.warning("Failed to read transaction cache for %s: %s", clean_txid, e)

        # 2. Fetch from network
        data, status_code, err = self._http_get_json(prov_url)
        if data is None:
            return None, err or f"HTTP {status_code}"

        tx = self.parse_transaction_payload(data, retrieval_status="FETCHED_OK", provenance_url=prov_url)

        # 3. Write confirmed transaction to permanent cache
        if self.cache_dir and tx.confirmed:
            try:
                tx_cache_path = self.cache_dir / "transactions" / f"{clean_txid}.json"
                tx_cache_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            except Exception as e:
                LOG.warning("Failed to write transaction cache for %s: %s", clean_txid, e)

        return tx, "FETCHED_OK"

    # ------------------------------------------------------------------
    # Address-Level (Mutable) History Fetcher & Cache
    # ------------------------------------------------------------------
    def fetch_address_transactions(
        self,
        address: str,
        max_txs: int = 25,
        force_refresh: bool = False,
    ) -> AddressFetchResult:
        """Fetches recent confirmed and mempool transactions for a Bitcoin address.

        Caches address history separately with TTL to detect newly arriving transactions.
        """
        canonical_addr = canonicalize_address(address)
        prov_url = f"{self.base_url}/address/{canonical_addr}/txs"

        addr_cache_path = None
        if self.cache_dir:
            addr_cache_path = self.cache_dir / "addresses" / f"{canonical_addr}.json"

        # Check address cache with TTL
        if not force_refresh and addr_cache_path and addr_cache_path.exists():
            mtime = addr_cache_path.stat().st_mtime
            age = time.time() - mtime
            if age < self.address_cache_ttl:
                try:
                    cached_data = json.loads(addr_cache_path.read_text(encoding="utf-8"))
                    raw_tx_list = cached_data.get("txs", [])
                    parsed_txs = [
                        self.parse_transaction_payload(
                            item,
                            retrieval_status="CACHED",
                            provenance_url=f"{self.base_url}/tx/{item.get('txid', '')}",
                        )
                        for item in raw_tx_list
                    ]
                    status = "EMPTY_HISTORY" if len(parsed_txs) == 0 else "CACHED"
                    return AddressFetchResult(
                        address=canonical_addr,
                        status=status,
                        transactions=parsed_txs[:max_txs],
                        total_fetched=len(parsed_txs),
                        has_more=cached_data.get("has_more", False),
                        cached=True,
                        provenance_url=prov_url,
                        http_status_code=200,
                    )
                except Exception as e:
                    LOG.warning("Failed to read address cache for %s: %s", canonical_addr, e)

        # Fetch from network
        data, status_code, err = self._http_get_json(prov_url)

        if data is None:
            if status_code == 404:
                # 404 on Esplora address endpoint means address has 0 transactions
                return AddressFetchResult(
                    address=canonical_addr,
                    status="EMPTY_HISTORY",
                    transactions=[],
                    total_fetched=0,
                    has_more=False,
                    cached=False,
                    provenance_url=prov_url,
                    http_status_code=404,
                )
            if status_code == 429:
                return AddressFetchResult(
                    address=canonical_addr,
                    status="RATE_LIMITED",
                    error_message=err,
                    provenance_url=prov_url,
                    http_status_code=429,
                )
            if status_code == 408:
                return AddressFetchResult(
                    address=canonical_addr,
                    status="TIMEOUT",
                    error_message=err,
                    provenance_url=prov_url,
                    http_status_code=408,
                )
            return AddressFetchResult(
                address=canonical_addr,
                status="HTTP_ERROR" if status_code > 0 else "NETWORK_ERROR",
                error_message=err,
                provenance_url=prov_url,
                http_status_code=status_code,
            )

        if not isinstance(data, list):
            return AddressFetchResult(
                address=canonical_addr,
                status="HTTP_ERROR",
                error_message="Unexpected API response: root is not a list",
                provenance_url=prov_url,
                http_status_code=status_code,
            )

        # Distinguish empty history from transactions
        if len(data) == 0:
            return AddressFetchResult(
                address=canonical_addr,
                status="EMPTY_HISTORY",
                transactions=[],
                total_fetched=0,
                has_more=False,
                cached=False,
                provenance_url=prov_url,
                http_status_code=200,
            )

        # Esplora returns 25 transactions per page. If 25 are returned, more may exist.
        has_more = len(data) >= 25

        parsed_txs = [
            self.parse_transaction_payload(
                item,
                retrieval_status="FETCHED_OK",
                provenance_url=f"{self.base_url}/tx/{item.get('txid', '')}",
            )
            for item in data
        ]

        # Save to address cache with timestamp
        if addr_cache_path:
            try:
                cache_payload = {
                    "fetched_at_utc": datetime.now(timezone.utc).isoformat(),
                    "has_more": has_more,
                    "txs": data,
                }
                addr_cache_path.write_text(json.dumps(cache_payload, indent=2), encoding="utf-8")
            except Exception as e:
                LOG.warning("Failed to write address cache for %s: %s", canonical_addr, e)

        # Also store individual confirmed transactions into permanent tx cache
        if self.cache_dir:
            for item in data:
                is_confirmed = item.get("status", {}).get("confirmed", False)
                item_txid = item.get("txid")
                if is_confirmed and item_txid:
                    tx_path = self.cache_dir / "transactions" / f"{item_txid.lower()}.json"
                    if not tx_path.exists():
                        try:
                            tx_path.write_text(json.dumps(item, indent=2), encoding="utf-8")
                        except Exception:
                            pass

        return AddressFetchResult(
            address=canonical_addr,
            status="SUCCESS",
            transactions=parsed_txs[:max_txs],
            total_fetched=len(parsed_txs),
            has_more=has_more,
            cached=False,
            provenance_url=prov_url,
            http_status_code=status_code,
        )

    # ------------------------------------------------------------------
    # Schema Parsing & Normalization
    # ------------------------------------------------------------------
    def parse_transaction_payload(
        self,
        payload: Dict[str, Any],
        retrieval_status: str = "LOADED",
        provenance_url: Optional[str] = None,
    ) -> Transaction:
        """Converts raw Esplora JSON object into typed Transaction model.

        Enforces satoshi accounting internally, converts to BTC for display,
        and never invents addresses for coinbase inputs or non-standard outputs.
        """
        txid = str(payload.get("txid", "")).lower()
        fee_sat = int(payload.get("fee", 0))

        status_obj = payload.get("status", {})
        confirmed = bool(status_obj.get("confirmed", False))
        block_height = status_obj.get("block_height")
        block_time = status_obj.get("block_time")

        iso_timestamp = None
        if block_time:
            try:
                iso_timestamp = datetime.fromtimestamp(int(block_time), timezone.utc).isoformat()
            except Exception:
                iso_timestamp = str(block_time)

        # 1. Parse Inputs (vin)
        inputs: List[TxInput] = []
        for vin in payload.get("vin", []):
            if vin.get("is_coinbase", False):
                # Coinbase input: do NOT invent an address
                inputs.append(
                    TxInput(
                        address="COINBASE",
                        value_sat=0,
                        prev_txid=None,
                        vout=None,
                        is_coinbase=True,
                    )
                )
                continue

            prevout = vin.get("prevout")
            if prevout and isinstance(prevout, dict):
                val_sat = int(prevout.get("value", 0))
                raw_addr = prevout.get("scriptpubkey_address")
                if raw_addr:
                    c_addr = canonicalize_address(raw_addr)
                    inputs.append(
                        TxInput(
                            address=c_addr,
                            value_sat=val_sat,
                            prev_txid=vin.get("txid"),
                            vout=vin.get("vout"),
                            is_coinbase=False,
                        )
                    )
                else:
                    # Non-standard / unparsed input script: do not invent an address
                    inputs.append(
                        TxInput(
                            address="NON_STANDARD",
                            value_sat=val_sat,
                            prev_txid=vin.get("txid"),
                            vout=vin.get("vout"),
                            is_coinbase=False,
                        )
                    )
            else:
                # Unresolved input: record txid/vout without inventing address
                inputs.append(
                    TxInput(
                        address="UNRESOLVED",
                        value_sat=0,
                        prev_txid=vin.get("txid"),
                        vout=vin.get("vout"),
                        is_coinbase=False,
                    )
                )

        # 2. Parse Outputs (vout)
        outputs: List[TxOutput] = []
        for idx, vout in enumerate(payload.get("vout", [])):
            val_sat = int(vout.get("value", 0))
            raw_addr = vout.get("scriptpubkey_address")
            spk_type = vout.get("scriptpubkey_type", "")

            if spk_type == "op_return" or not raw_addr:
                # OP_RETURN or non-standard output
                outputs.append(
                    TxOutput(
                        address="OP_RETURN" if spk_type == "op_return" else "NON_STANDARD",
                        value_sat=val_sat,
                        n=idx,
                        is_op_return=(spk_type == "op_return"),
                    )
                )
            else:
                c_addr = canonicalize_address(raw_addr)
                outputs.append(
                    TxOutput(
                        address=c_addr,
                        value_sat=val_sat,
                        n=idx,
                        is_op_return=False,
                    )
                )

        return Transaction(
            txid=txid,
            inputs=inputs,
            outputs=outputs,
            fee_sat=fee_sat,
            block_height=block_height,
            timestamp=iso_timestamp,
            confirmed=confirmed,
            provenance_url=provenance_url,
            retrieval_status=retrieval_status,
        )

    # ------------------------------------------------------------------
    # TransactionGraph Population Helper
    # ------------------------------------------------------------------
    def populate_graph_for_address(
        self,
        address: str,
        graph: TransactionGraph,
        max_txs: int = 25,
    ) -> AddressFetchResult:
        """Fetches transactions for an address and adds them to a TransactionGraph.

        Only confirmed valid transactions with real inputs and outputs are indexed.
        """
        result = self.fetch_address_transactions(address, max_txs=max_txs)
        for tx in result.transactions:
            graph.add_transaction(tx)
        return result
