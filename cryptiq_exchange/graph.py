"""Graph representation of UTXO and account-based blockchain transactions."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .address import canonicalize_address

LOG = logging.getLogger("cryptiq.graph")


@dataclass
class TxInput:
    """Input spent in a transaction."""
    address: str
    value: float = 0.0  # In native coin units (BTC/ETH) for display
    value_sat: Optional[int] = None  # Exact integer satoshis for accounting
    prev_txid: Optional[str] = None
    vout: Optional[int] = None
    is_coinbase: bool = False

    def __post_init__(self):
        if self.value_sat is not None and self.value == 0.0:
            self.value = self.value_sat / 100_000_000.0
        elif self.value != 0.0 and self.value_sat is None:
            self.value_sat = int(round(self.value * 100_000_000))


@dataclass
class TxOutput:
    """Output created in a transaction."""
    address: str
    value: float = 0.0  # In native coin units (BTC/ETH) for display
    value_sat: Optional[int] = None  # Exact integer satoshis for accounting
    n: int = 0
    is_op_return: bool = False

    def __post_init__(self):
        if self.value_sat is not None and self.value == 0.0:
            self.value = self.value_sat / 100_000_000.0
        elif self.value != 0.0 and self.value_sat is None:
            self.value_sat = int(round(self.value * 100_000_000))


@dataclass
class Transaction:
    """Blockchain transaction record containing inputs and outputs."""
    txid: str
    inputs: List[TxInput] = field(default_factory=list)
    outputs: List[TxOutput] = field(default_factory=list)
    fee: float = 0.0
    fee_sat: Optional[int] = None
    block_height: Optional[int] = None
    timestamp: Optional[str] = None
    confirmed: bool = True
    provenance_url: Optional[str] = None
    retrieval_status: str = "LOADED"

    def __post_init__(self):
        if self.fee_sat is not None and self.fee == 0.0:
            self.fee = self.fee_sat / 100_000_000.0
        elif self.fee != 0.0 and self.fee_sat is None:
            self.fee_sat = int(round(self.fee * 100_000_000))

    @property
    def total_input_sat(self) -> int:
        return sum(inp.value_sat or 0 for inp in self.inputs)

    @property
    def total_output_sat(self) -> int:
        return sum(out.value_sat or 0 for out in self.outputs)

    @property
    def total_input_value(self) -> float:
        return sum(inp.value for inp in self.inputs)

    @property
    def total_output_value(self) -> float:
        return sum(out.value for out in self.outputs)


class TransactionGraph:
    """Directed graph of blockchain transactions enabling forward and backward tracing."""

    def __init__(self):
        # txid -> Transaction
        self.transactions: Dict[str, Transaction] = {}
        # canonical_address -> list of txids where address is an INPUT (funds leaving address)
        self._spending_index: Dict[str, List[str]] = {}
        # canonical_address -> list of txids where address is an OUTPUT (funds received by address)
        self._receiving_index: Dict[str, List[str]] = {}

    def add_transaction(self, tx: Transaction) -> None:
        """Adds a transaction and updates the spending and receiving indices."""
        self.transactions[tx.txid] = tx

        for inp in tx.inputs:
            if inp.is_coinbase or inp.address in ("COINBASE", ""):
                continue
            c_addr = canonicalize_address(inp.address)
            self._spending_index.setdefault(c_addr, []).append(tx.txid)

        for out in tx.outputs:
            if out.is_op_return or out.address in ("OP_RETURN", "NON_STANDARD", ""):
                continue
            c_addr = canonicalize_address(out.address)
            self._receiving_index.setdefault(c_addr, []).append(tx.txid)

    def add_transfer(
        self,
        from_address: str,
        to_address: str,
        value: float,
        txid: str,
        fee: float = 0.0,
        block_height: Optional[int] = None,
        timestamp: Optional[str] = None,
    ) -> Transaction:
        """Helper to create and add a single 1-to-1 transfer transaction."""
        c_from = canonicalize_address(from_address)
        c_to = canonicalize_address(to_address)
        tx = Transaction(
            txid=txid,
            inputs=[TxInput(address=c_from, value=value + fee)],
            outputs=[TxOutput(address=c_to, value=value, n=0)],
            fee=fee,
            block_height=block_height,
            timestamp=timestamp,
        )
        self.add_transaction(tx)
        return tx

    def get_forward_transactions(self, address: str) -> List[Transaction]:
        """Returns all transactions where the given address spent funds."""
        c_addr = canonicalize_address(address)
        txids = self._spending_index.get(c_addr, [])
        return [self.transactions[tid] for tid in txids if tid in self.transactions]

    def get_receiving_transactions(self, address: str) -> List[Transaction]:
        """Returns all transactions where the given address received funds."""
        c_addr = canonicalize_address(address)
        txids = self._receiving_index.get(c_addr, [])
        return [self.transactions[tid] for tid in txids if tid in self.transactions]

    def get_adjacent_outputs(self, address: str) -> List[Tuple[Transaction, TxOutput]]:
        """Finds all outputs directly downstream from this address."""
        forward_txs = self.get_forward_transactions(address)
        adjacent: List[Tuple[Transaction, TxOutput]] = []
        for tx in forward_txs:
            for out in tx.outputs:
                adjacent.append((tx, out))
        return adjacent

    def summary(self) -> Dict[str, int]:
        return {
            "total_transactions": len(self.transactions),
            "spending_addresses_indexed": len(self._spending_index),
            "receiving_addresses_indexed": len(self._receiving_index),
        }
