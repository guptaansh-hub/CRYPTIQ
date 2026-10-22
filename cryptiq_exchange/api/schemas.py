"""Pydantic schemas and request/response models for the CRYPTIQ REST API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class InvestigateRequest(BaseModel):
    """Request payload for suspect address forensic investigation."""
    address: str = Field(
        ...,
        description="Victim-reported suspect cryptocurrency wallet address",
        min_length=14,
        max_length=90,
    )
    case_id: Optional[str] = Field(
        None,
        description="Optional custom tracking case ID (e.g. CASE-2026-SIH26183-001)",
        pattern=r"^[A-Za-z0-9_-]{1,64}$",
    )
    max_hops: int = Field(
        4,
        ge=1,
        le=10,
        description="Maximum transaction hops forward to trace towards exchange deposit wallets",
    )
    taint_model: str = Field(
        "haircut",
        pattern=r"^(haircut|fifo)$",
        description="Taint accounting algorithm: 'haircut' (proportional) or 'fifo' (first-in first-out)",
    )
    enable_network_fetching: bool = Field(
        False,
        description="Explicit opt-in to fetch live/cached on-chain transaction history via Esplora (default: False)",
    )
    currency_hint: Optional[str] = Field(
        None,
        pattern=r"^(BTC|ETH)$",
        description="Optional currency override hint (BTC or ETH)",
    )
    max_fetch_txs: int = Field(
        25,
        ge=1,
        le=50,
        description="Maximum transactions to fetch per address (default: 25, bounded by page size)",
    )


class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str
    service: str
    version: str
    problem_statement: str
    entities_loaded: Dict[str, Any]
    network_adapter: Dict[str, Any]


class EntityStatsResponse(BaseModel):
    """Entity and TagPack statistics response schema."""
    total_records: int
    by_category: Dict[str, int]
    by_actor: Dict[str, int]
    by_confidence: Dict[str, int]
    tagpacks: List[Dict[str, Any]]
