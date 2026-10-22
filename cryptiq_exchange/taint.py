"""Taint calculation models for cryptocurrency flow tracking.

Implements two primary forensic taint tracking methodologies:
1. Proportional / Haircut Taint:
   Blends taint across all transaction outputs proportionally to their output value.
2. FIFO (First-In, First-Out) Taint:
   Attributes taint sequentially in order of output index until the tainted amount is exhausted.
"""

from __future__ import annotations

from typing import Dict, List, Tuple
from .graph import Transaction, TxOutput


def calculate_haircut_taint(
    tx: Transaction,
    spending_address: str,
    incoming_taint_ratio: float,
) -> Dict[str, Tuple[float, float]]:
    """Calculates proportional (haircut) taint for all outputs of a transaction.

    Args:
        tx: The Transaction object
        spending_address: Canonical address that supplied tainted funds into this tx
        incoming_taint_ratio: Taint fraction of the spending address [0.0, 1.0]

    Returns:
        Dict mapping output_address -> (taint_ratio, taint_amount_in_native_units)
    """
    total_in = tx.total_input_value
    if total_in <= 0.0:
        # Fallback to sum of outputs if input values were not recorded
        total_in = tx.total_output_value
    if total_in <= 0.0:
        return {}

    # Calculate tainted volume contributed by the spending address
    spent_value = 0.0
    for inp in tx.inputs:
        if inp.address == spending_address:
            spent_value += inp.value

    # If spent_value is 0 (e.g. simplified single-value graph), assume the spending address
    # provided the full transaction input:
    if spent_value == 0.0 and len(tx.inputs) == 1:
        spent_value = total_in

    tainted_in_amount = spent_value * max(0.0, min(1.0, incoming_taint_ratio))
    tx_blended_taint_ratio = tainted_in_amount / total_in if total_in > 0 else 0.0

    output_taints: Dict[str, Tuple[float, float]] = {}
    for out in tx.outputs:
        out_taint_amount = out.value * tx_blended_taint_ratio
        output_taints[out.address] = (tx_blended_taint_ratio, out_taint_amount)

    return output_taints


def calculate_fifo_taint(
    tx: Transaction,
    spending_address: str,
    incoming_taint_ratio: float,
) -> Dict[str, Tuple[float, float]]:
    """Calculates FIFO taint, assigning tainted value sequentially to outputs.

    Outputs are prioritized by index n until incoming tainted volume is exhausted.
    """
    total_in = tx.total_input_value or tx.total_output_value
    if total_in <= 0.0:
        return {}

    spent_value = sum(inp.value for inp in tx.inputs if inp.address == spending_address)
    if spent_value == 0.0 and len(tx.inputs) == 1:
        spent_value = total_in

    remaining_taint = spent_value * max(0.0, min(1.0, incoming_taint_ratio))
    output_taints: Dict[str, Tuple[float, float]] = {}

    sorted_outputs = sorted(tx.outputs, key=lambda o: o.n)
    for out in sorted_outputs:
        if remaining_taint <= 0.0 or out.value <= 0.0:
            output_taints[out.address] = (0.0, 0.0)
            continue

        assigned_taint = min(remaining_taint, out.value)
        out_ratio = assigned_taint / out.value if out.value > 0 else 0.0
        output_taints[out.address] = (out_ratio, assigned_taint)
        remaining_taint -= assigned_taint

    return output_taints
