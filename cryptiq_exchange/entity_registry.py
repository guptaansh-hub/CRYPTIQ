"""Unified in-memory registry of authenticated blockchain entity attributions."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .address import canonicalize_address
from .models import AttributionRecord
from .tagpack import TagPack, TagPackParser

LOG = logging.getLogger("cryptiq.registry")


class EntityRegistry:
    """Stores and indexes verified entity attributions for O(1) lookup."""

    def __init__(self):
        # (canonical_address, currency) -> AttributionRecord
        self._address_map: Dict[Tuple[str, str], AttributionRecord] = {}
        # canonical_address -> AttributionRecord (currency agnostic fallback)
        self._generic_address_map: Dict[str, AttributionRecord] = {}
        self._loaded_tagpacks: List[TagPack] = []

    def register_tagpack(self, tagpack: TagPack) -> int:
        """Registers all records from a TagPack into the lookup index."""
        count = 0
        for rec in tagpack.records:
            key_with_curr = (rec.address, rec.currency.upper())
            self._address_map[key_with_curr] = rec
            self._generic_address_map[rec.address] = rec
            count += 1
        self._loaded_tagpacks.append(tagpack)
        LOG.debug("Registered %d records from TagPack '%s'", count, tagpack.title)
        return count

    def load_tagpack_file(self, file_path: str | Path) -> TagPack:
        """Parses a YAML tagpack file and registers it."""
        tp = TagPackParser.parse_file(file_path)
        self.register_tagpack(tp)
        return tp

    def load_known_raw_tagpacks(self, raw_dir: str | Path) -> Dict[str, TagPack]:
        """Loads default verified GraphSense and EtherScamDB tagpacks if present."""
        p = Path(raw_dir)
        loaded = {}
        candidates = [
            "exchange-wallets-binance.yaml",
            "exchange-wallets-bybit.yaml",
            "etherscamdb_tagpack.yaml",
        ]
        for name in candidates:
            f = p / name
            if f.exists():
                try:
                    tp = self.load_tagpack_file(f)
                    loaded[name] = tp
                except Exception as e:
                    LOG.error("Failed to load tagpack %s: %s", f, e)
        return loaded

    def lookup(
        self, address: str, currency: Optional[str] = None
    ) -> Optional[AttributionRecord]:
        """Queries the registry for verified attribution metadata.

        Returns None if the address has no verified disclosure entry (strictly uninvented).
        """
        canonical = canonicalize_address(address)
        if currency:
            key = (canonical, currency.upper())
            if key in self._address_map:
                return self._address_map[key]

        # Currency-agnostic match
        return self._generic_address_map.get(canonical)

    def is_exchange(self, address: str, currency: Optional[str] = None) -> bool:
        """Returns True if the address is confirmed to belong to a cryptocurrency exchange."""
        rec = self.lookup(address, currency)
        if rec and rec.category == "exchange":
            return True
        return False

    def is_known_scam(self, address: str, currency: Optional[str] = None) -> bool:
        """Returns True if the address has a confirmed abuse flag (e.g. phishing/scam)."""
        rec = self.lookup(address, currency)
        if rec and (rec.category in ("scam", "phishing") or rec.abuse is not None):
            return True
        return False

    def get_known_exchanges(self) -> Set[str]:
        """Returns the set of unique exchange entity names registered."""
        return {
            rec.actor
            for rec in self._generic_address_map.values()
            if rec.category == "exchange"
        }

    def summary(self) -> Dict[str, Any]:
        """Returns statistical overview of the loaded attribution registry."""
        exchanges = set()
        scams = set()
        conf_counts: Dict[str, int] = {}
        category_counts: Dict[str, int] = {}

        for rec in self._generic_address_map.values():
            cat = rec.category
            category_counts[cat] = category_counts.get(cat, 0) + 1
            conf = rec.confidence
            conf_counts[conf] = conf_counts.get(conf, 0) + 1
            if cat == "exchange":
                exchanges.add(rec.actor)
            if cat in ("scam", "phishing"):
                scams.add(rec.actor)

        return {
            "total_unique_addresses": len(self._generic_address_map),
            "loaded_tagpacks_count": len(self._loaded_tagpacks),
            "registered_exchanges": sorted(list(exchanges)),
            "categories": category_counts,
            "confidence_tiers": conf_counts,
        }

    @property
    def loaded_tagpacks(self) -> List[TagPack]:
        return self._loaded_tagpacks

    @property
    def records(self) -> Dict[str, AttributionRecord]:
        return self._generic_address_map

