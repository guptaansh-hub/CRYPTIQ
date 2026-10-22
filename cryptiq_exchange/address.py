"""Address validation, format detection, and canonicalization for Bitcoin and Ethereum."""

from __future__ import annotations

import re
import hashlib
from typing import Tuple
from .models import AddressInfo

# Bitcoin Base58 characters (excludes 0, O, I, l)
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_SET = set(B58_ALPHABET)

# Bech32 characters (excludes 1, b, i, o)
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_SET = set(BECH32_CHARSET)

ETH_HEX_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _decode_base58(s: str) -> bytes | None:
    """Decodes a Base58Check string into raw bytes with checksum verification."""
    if not all(c in B58_SET for c in s):
        return None
    num = 0
    for char in s:
        num = num * 58 + B58_ALPHABET.index(char)
    combined = num.to_bytes(25, byteorder="big")
    payload, checksum = combined[:-4], combined[-4:]
    expected_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected_checksum:
        return None
    return payload


def is_valid_btc_base58(addr: str) -> Tuple[bool, str]:
    """Validates Bitcoin P2PKH (starts with 1) or P2SH (starts with 3)."""
    if len(addr) < 26 or len(addr) > 35:
        return False, "invalid"
    if addr[0] not in ("1", "3"):
        return False, "invalid"
    payload = _decode_base58(addr)
    if payload is None:
        return False, "invalid"
    version = payload[0]
    if version == 0x00 and addr[0] == "1":
        return True, "p2pkh"
    if version == 0x05 and addr[0] == "3":
        return True, "p2sh"
    return False, "invalid"


def is_valid_btc_bech32(addr: str) -> Tuple[bool, str]:
    """Validates Bitcoin Native SegWit (P2WPKH / P2WSH) or Taproot Bech32/Bech32m."""
    lower = addr.lower()
    if not lower.startswith("bc1"):
        return False, "invalid"
    if len(lower) < 14 or len(lower) > 90:
        return False, "invalid"
    data_part = lower[3:]
    if not all(c in BECH32_SET for c in data_part):
        return False, "invalid"
    if lower.startswith("bc1q"):
        return True, "bech32_segwit"
    if lower.startswith("bc1p"):
        return True, "bech32m_taproot"
    return True, "bech32_other"


def is_valid_eth_address(addr: str) -> Tuple[bool, str]:
    """Validates an Ethereum 20-byte hex address (with 0x prefix)."""
    if not ETH_HEX_PATTERN.match(addr):
        return False, "invalid"
    return True, "eth_hex"


def canonicalize_address(addr: str) -> str:
    """Strips leading/trailing whitespace and normalizes format-dependent casing.
    Note: Bitcoin Base58 addresses preserve case; Bech32 and Ethereum hex are lowercased.
    """
    clean = addr.strip()
    if clean.lower().startswith("bc1"):
        return clean.lower()
    if clean.startswith("0x") or clean.startswith("0X"):
        return clean.lower()
    return clean


def validate_address(raw_address: str) -> AddressInfo:
    """Validates and classifies any victim-reported or transaction address.

    Returns an AddressInfo dataclass containing canonical address, network, format,
    and validity flag.
    """
    if not isinstance(raw_address, str) or not raw_address.strip():
        return AddressInfo(
            raw_address=str(raw_address),
            canonical_address="",
            network="UNKNOWN",
            address_format="invalid",
            is_valid=False,
        )

    clean = canonicalize_address(raw_address)

    # 1. Bitcoin Base58 (P2PKH / P2SH)
    if clean.startswith("1") or clean.startswith("3"):
        valid, fmt = is_valid_btc_base58(clean)
        if valid:
            return AddressInfo(
                raw_address=raw_address,
                canonical_address=clean,
                network="BTC",
                address_format=fmt,
                is_valid=True,
            )

    # 2. Bitcoin Bech32 (SegWit / Taproot)
    if clean.startswith("bc1"):
        valid, fmt = is_valid_btc_bech32(clean)
        if valid:
            return AddressInfo(
                raw_address=raw_address,
                canonical_address=clean,
                network="BTC",
                address_format=fmt,
                is_valid=True,
            )

    # 3. Ethereum Hex
    if clean.startswith("0x"):
        valid, fmt = is_valid_eth_address(clean)
        if valid:
            return AddressInfo(
                raw_address=raw_address,
                canonical_address=clean,
                network="ETH",
                address_format=fmt,
                is_valid=True,
            )

    return AddressInfo(
        raw_address=raw_address,
        canonical_address=clean,
        network="UNKNOWN",
        address_format="invalid",
        is_valid=False,
    )
