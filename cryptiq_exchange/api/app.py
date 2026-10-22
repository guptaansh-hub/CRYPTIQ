"""FastAPI application exposing CRYPTIQ exchange identification and forensic reporting."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ..adapters.esplora import EsploraBitcoinAdapter
from ..address import validate_address
from ..cli import format_markdown_report, resolve_raw_dir
from ..engine import ExchangeIdentificationEngine
from ..entity_registry import EntityRegistry
from .schemas import (
    EntityStatsResponse,
    HealthResponse,
    InvestigateRequest,
)

LOG = logging.getLogger("cryptiq.api")
SAFE_CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DEFAULT_INVESTIGATIONS_DIR = Path("data/processed/investigations")


def create_app(
    raw_dir: Optional[str | Path] = None,
    investigations_dir: Optional[str | Path] = None,
    cache_dir: Optional[str | Path] = None,
    registry: Optional[EntityRegistry] = None,
    engine: Optional[ExchangeIdentificationEngine] = None,
) -> FastAPI:
    """Application factory for the CRYPTIQ REST API."""
    app = FastAPI(
        title="CRYPTIQ Forensic Investigation API",
        description=(
            "SIH26183: Real-Time Identification of Fraud-Linked Cryptocurrency Exchanges "
            "from Victim-Reported Suspect Wallet Addresses through Automated Blockchain Analytics."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Enable CORS for future frontend integration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Initialize or reuse registry and engine
    resolved_inv_dir = Path(investigations_dir or DEFAULT_INVESTIGATIONS_DIR).resolve()
    resolved_inv_dir.mkdir(parents=True, exist_ok=True)

    if registry is not None and engine is not None:
        reg = registry
        eng = engine
    elif engine is not None:
        eng = engine
        reg = engine.registry
    else:
        reg = registry or EntityRegistry()
        try:
            target_raw = resolve_raw_dir(raw_dir)
            reg.load_known_raw_tagpacks(target_raw)
            LOG.info("Loaded verified TagPacks from %s", target_raw)
        except Exception as e:
            LOG.warning("Could not auto-load raw TagPacks on API startup: %s", e)
        eng = ExchangeIdentificationEngine(registry=reg)

    # Store state on app
    app.state.registry = reg
    app.state.engine = eng
    app.state.investigations_dir = resolved_inv_dir
    app.state.cache_dir = Path(cache_dir or "data/cache/esplora")

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------

    @app.get(
        "/api/v1/health",
        response_model=HealthResponse,
        summary="Service Health and Dependency Status",
        tags=["System"],
    )
    def health_check() -> Dict[str, Any]:
        """Returns API health status, loaded entity counts, and network adapter configuration."""
        tagpacks_count = len(app.state.registry.loaded_tagpacks)
        total_records = len(app.state.registry.records)
        exchanges = sorted(list(app.state.registry.get_known_exchanges()))

        return {
            "status": "healthy",
            "service": "CRYPTIQ Forensic Analytics Engine",
            "version": "1.0.0",
            "problem_statement": "SIH26183",
            "entities_loaded": {
                "tagpacks_count": tagpacks_count,
                "total_records": total_records,
                "exchanges": exchanges,
            },
            "network_adapter": {
                "default_mode": "disabled (offline)",
                "adapter": "EsploraBitcoinAdapter",
                "cache_dir": str(app.state.cache_dir.name),
            },
        }

    @app.get(
        "/api/v1/entities",
        response_model=EntityStatsResponse,
        summary="Attribution Entity and TagPack Statistics",
        tags=["Attribution"],
    )
    def get_entity_stats() -> Dict[str, Any]:
        """Returns aggregated breakdown of verified exchange disclosures and scam abuse records."""
        reg_obj: EntityRegistry = app.state.registry
        by_category: Dict[str, int] = {}
        by_actor: Dict[str, int] = {}
        by_confidence: Dict[str, int] = {}

        for rec in reg_obj.records.values():
            cat = rec.category or "unknown"
            by_category[cat] = by_category.get(cat, 0) + 1

            act = rec.actor or "unattributed"
            by_actor[act] = by_actor.get(act, 0) + 1

            conf = rec.confidence or "unverified"
            by_confidence[conf] = by_confidence.get(conf, 0) + 1

        tagpack_summaries = [
            {
                "title": tp.title,
                "actor": tp.actor,
                "category": tp.category,
                "confidence": tp.confidence,
                "source": tp.source,
                "is_cluster_definer": tp.is_cluster_definer,
                "records_count": len(tp.records),
            }
            for tp in reg_obj.loaded_tagpacks
        ]

        return {
            "total_records": len(reg_obj.records),
            "by_category": by_category,
            "by_actor": by_actor,
            "by_confidence": by_confidence,
            "tagpacks": tagpack_summaries,
        }

    @app.post(
        "/api/v1/investigate",
        summary="Investigate Suspect Cryptocurrency Address",
        tags=["Investigation"],
    )
    def investigate_address(payload: InvestigateRequest) -> JSONResponse:
        """Validates a suspect wallet address, runs flow tracing and exchange identification,

        saves the reproducible case report, and returns the structured evidentiary report.
        """
        # 1. Cryptographic address validation
        addr_info = validate_address(payload.address)
        if not addr_info.is_valid:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    f"Address '{payload.address}' failed cryptographic validation for supported networks "
                    "(Bitcoin Base58 P2PKH/P2SH, Bech32/Bech32m, Ethereum Hex)."
                ),
            )

        # 2. Setup optional network fetching adapter
        adapter = None
        if payload.enable_network_fetching:
            adapter = EsploraBitcoinAdapter(
                cache_dir=app.state.cache_dir,
            )

        # 3. Execute investigation via engine
        engine_obj: ExchangeIdentificationEngine = app.state.engine
        report = engine_obj.investigate_suspect_address(
            suspect_address=payload.address,
            max_hops=payload.max_hops,
            taint_model=payload.taint_model,
            currency_hint=payload.currency_hint,
            case_id=payload.case_id,
            enable_network_fetching=payload.enable_network_fetching,
            adapter=adapter,
            max_fetch_txs_per_address=payload.max_fetch_txs,
        )

        report_dict = report.to_dict()

        # 4. Save reproducible case files to investigations directory
        try:
            inv_dir = app.state.investigations_dir
            json_path = inv_dir / f"{report.case_id}.json"
            md_path = inv_dir / f"{report.case_id}.md"

            json_path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
            md_content = format_markdown_report(report_dict)
            md_path.write_text(md_content, encoding="utf-8")
        except Exception as e:
            LOG.error("Failed to persist case reports for %s: %s", report.case_id, e)

        return JSONResponse(status_code=status.HTTP_200_OK, content=report_dict)

    @app.get(
        "/api/v1/cases/{case_id}",
        summary="Retrieve Saved Case Investigation Report",
        tags=["Investigation"],
    )
    def get_case_report(case_id: str) -> JSONResponse:
        """Safely retrieves a previously saved case investigation report by case ID.

        Enforces strict path traversal safeguards and hides internal filesystem paths.
        """
        # Validate case_id format to prevent directory traversal
        if not SAFE_CASE_ID_PATTERN.match(case_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid case ID format. Must be alphanumeric with hyphens or underscores (1-64 characters).",
            )

        inv_dir: Path = app.state.investigations_dir
        target_file = (inv_dir / f"{case_id}.json").resolve()

        # Ensure target file is strictly within the investigations directory
        if not str(target_file).startswith(str(inv_dir)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access to specified resource is restricted.",
            )

        if not target_file.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case report '{case_id}' was not found.",
            )

        try:
            data = json.loads(target_file.read_text(encoding="utf-8"))
            return JSONResponse(status_code=status.HTTP_200_OK, content=data)
        except Exception as e:
            LOG.error("Error reading case report %s: %s", case_id, e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to read the requested case report.",
            )

    return app


# Module-level default application instance for uvicorn
app = create_app()
