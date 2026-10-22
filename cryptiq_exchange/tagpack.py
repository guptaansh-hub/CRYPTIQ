"""Parser and schema validator for GraphSense TagPacks and abuse lists."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .address import canonicalize_address
from .models import AttributionRecord

LOG = logging.getLogger("cryptiq.tagpack")

VALID_CONFIDENCES = {"service_data", "curated", "unverified", "web_scraping"}


class TagPack:
    """In-memory representation of an authenticated TagPack."""

    def __init__(
        self,
        title: str,
        creator: str,
        confidence: str,
        category: str,
        source: str,
        actor: str,
        description: str = "",
        lastmod: str = "",
        is_cluster_definer: bool = False,
        records: Optional[List[AttributionRecord]] = None,
    ):
        self.title = title
        self.creator = creator
        self.confidence = confidence if confidence in VALID_CONFIDENCES else "unverified"
        self.category = category
        self.source = source
        self.actor = actor
        self.description = description
        self.lastmod = lastmod
        self.is_cluster_definer = is_cluster_definer
        self.records: List[AttributionRecord] = records or []

    def __repr__(self) -> str:
        return (
            f"<TagPack title='{self.title}' actor='{self.actor}' "
            f"category='{self.category}' records={len(self.records)}>"
        )


class TagPackParser:
    """Parses and validates GraphSense TagPack files (e.g. Binance, Bybit, EtherScamDB)."""

    @staticmethod
    def parse_file(file_path: str | Path) -> TagPack:
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"TagPack file not found: {p}")

        LOG.info("Loading TagPack from %s...", p)
        with open(p, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError(f"Invalid TagPack format in {p}: root must be a YAML mapping")

        title = str(data.get("title", p.stem))
        creator = str(data.get("creator", "Unknown"))
        header_conf = str(data.get("confidence", "curated")).lower()
        header_cat = str(data.get("category", "unattributed")).lower()
        header_src = str(data.get("source", ""))
        header_actor = str(data.get("actor", "")).lower()
        description = str(data.get("description", ""))
        lastmod = str(data.get("lastmod", ""))
        is_cluster_definer = bool(data.get("is_cluster_definer", False))

        raw_tags = data.get("tags", [])
        if not isinstance(raw_tags, list):
            raise ValueError(f"TagPack {p} missing valid 'tags' list")

        records: List[AttributionRecord] = []
        for idx, tag in enumerate(raw_tags):
            if not isinstance(tag, dict) or "address" not in tag:
                continue

            raw_addr = str(tag["address"]).strip()
            if not raw_addr:
                continue

            clean_addr = canonicalize_address(raw_addr)
            currency = str(tag.get("currency", "UNKNOWN")).upper()
            label = str(tag.get("label", title))
            tag_src = str(tag.get("source", header_src))
            tag_cat = str(tag.get("category", header_cat)).lower()
            tag_actor = str(tag.get("actor", header_actor)).lower()
            tag_conf = str(tag.get("confidence", header_conf)).lower()
            abuse = str(tag["abuse"]).lower() if "abuse" in tag else None

            # Infer category if missing but abuse is present
            if tag_cat in ("unattributed", "") and abuse:
                tag_cat = "scam"

            rec = AttributionRecord(
                address=clean_addr,
                currency=currency,
                actor=tag_actor if tag_actor else (abuse or "unattributed"),
                category=tag_cat,
                confidence=tag_conf if tag_conf in VALID_CONFIDENCES else "unverified",
                source=tag_src,
                label=label,
                is_cluster_definer=is_cluster_definer,
                abuse=abuse,
            )
            records.append(rec)

        LOG.info(
            "Parsed TagPack '%s' (%s): %d valid attribution records.",
            title,
            header_actor or header_cat,
            len(records),
        )

        return TagPack(
            title=title,
            creator=creator,
            confidence=header_conf,
            category=header_cat,
            source=header_src,
            actor=header_actor,
            description=description,
            lastmod=lastmod,
            is_cluster_definer=is_cluster_definer,
            records=records,
        )
