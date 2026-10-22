"""Multi-hop blockchain transaction flow tracing and exchange discovery."""

from __future__ import annotations

import logging
from collections import deque
from typing import List, Optional, Set

from .address import canonicalize_address
from .entity_registry import EntityRegistry
from .graph import TransactionGraph
from .models import HopStep, TracePath
from .taint import calculate_fifo_taint, calculate_haircut_taint

LOG = logging.getLogger("cryptiq.tracer")


class BlockchainTracer:
    """Traces transaction paths forward from a victim-reported suspect address."""

    def __init__(
        self,
        graph: TransactionGraph,
        registry: EntityRegistry,
        taint_model: str = "haircut",
        max_hops: int = 4,
        min_taint_threshold: float = 1e-6,
        stop_at_exchange: bool = True,
    ):
        self.graph = graph
        self.registry = registry
        self.taint_model = taint_model.lower()
        self.max_hops = max_hops
        self.min_taint_threshold = min_taint_threshold
        self.stop_at_exchange = stop_at_exchange

    def trace_from_suspect(
        self,
        suspect_address: str,
        initial_taint_ratio: float = 1.0,
    ) -> List[TracePath]:
        """Performs BFS forward traversal along transaction graph edges.

        Args:
            suspect_address: Victim-reported address under investigation
            initial_taint_ratio: Initial taint score (1.0 = 100% tainted)

        Returns:
            List of complete TracePath objects terminating at exchange wallets
            or maximum hop depth.
        """
        start_addr = canonicalize_address(suspect_address)
        LOG.info("Starting trace from suspect address: %s (max_hops=%d)", start_addr, self.max_hops)

        completed_paths: List[TracePath] = []
        path_counter = 0

        # Queue item: (current_address, current_taint_ratio, list_of_hop_steps, visited_set)
        queue = deque([(start_addr, initial_taint_ratio, [], {start_addr})])

        while queue:
            curr_addr, curr_taint_ratio, steps, visited = queue.popleft()
            curr_hop = len(steps)

            if curr_hop >= self.max_hops:
                # Reached depth limit without hitting exchange stop condition
                if steps:
                    path_counter += 1
                    completed_paths.append(
                        self._build_trace_path(
                            path_id=f"path_{path_counter}",
                            steps=steps,
                        )
                    )
                continue

            forward_txs = self.graph.get_forward_transactions(curr_addr)
            if not forward_txs:
                # Terminal unspent address (leaf node)
                if steps:
                    path_counter += 1
                    completed_paths.append(
                        self._build_trace_path(
                            path_id=f"path_{path_counter}",
                            steps=steps,
                        )
                    )
                continue

            for tx in forward_txs:
                # Calculate taint propagation
                if self.taint_model == "fifo":
                    output_taints = calculate_fifo_taint(tx, curr_addr, curr_taint_ratio)
                else:
                    output_taints = calculate_haircut_taint(tx, curr_addr, curr_taint_ratio)

                for out in tx.outputs:
                    out_addr = out.address
                    out_ratio, out_taint_amount = output_taints.get(out_addr, (0.0, 0.0))

                    if out_taint_amount < self.min_taint_threshold:
                        continue

                    # Avoid circular loops in the same trace path
                    if out_addr in visited:
                        continue

                    # Attribution lookup
                    attribution = self.registry.lookup(out_addr)

                    hop = HopStep(
                        hop_number=curr_hop + 1,
                        txid=tx.txid,
                        from_address=curr_addr,
                        to_address=out_addr,
                        value=out.value,
                        taint_ratio=out_ratio,
                        taint_amount=out_taint_amount,
                        block_height=tx.block_height,
                        timestamp=tx.timestamp,
                        attribution=attribution,
                    )

                    new_steps = steps + [hop]
                    new_visited = visited | {out_addr}

                    # Check if reached exchange
                    is_exchange = (
                        attribution is not None and attribution.category == "exchange"
                    )

                    if is_exchange and self.stop_at_exchange:
                        path_counter += 1
                        completed_paths.append(
                            self._build_trace_path(
                                path_id=f"path_{path_counter}",
                                steps=new_steps,
                            )
                        )
                    else:
                        queue.append((out_addr, out_ratio, new_steps, new_visited))

        LOG.info("Tracing completed: discovered %d paths from %s.", len(completed_paths), start_addr)
        return completed_paths

    def _build_trace_path(self, path_id: str, steps: List[HopStep]) -> TracePath:
        last_step = steps[-1]
        first_step = steps[0]
        return TracePath(
            path_id=path_id,
            steps=steps,
            terminating_address=last_step.to_address,
            terminating_attribution=last_step.attribution,
            total_hops=len(steps),
            initial_taint_sent=first_step.taint_amount,
            terminating_value=last_step.value,
            terminating_taint=last_step.taint_amount,
        )
