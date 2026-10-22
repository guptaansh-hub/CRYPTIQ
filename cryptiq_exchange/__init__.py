"""CRYPTIQ Exchange Identification and Blockchain Analytics Package.

Part of CRYPTIQ - SIH 26183: Real-Time Identification of Fraud-Linked Cryptocurrency
Exchanges from Victim-Reported Suspect Wallet Addresses through Automated Blockchain Analytics.

Core Principles & Safeguards:
1. Verifiable Provenance: Entity attribution relies exclusively on verified external
   disclosures and tagpacks (e.g. GraphSense service disclosures, EtherScamDB).
2. Separation of Concerns: Transaction-level risk scoring is strictly separated from
   entity identity attribution and fraud-linkage conclusions.
3. Evidentiary Boundary: A transaction connection to an exchange wallet proves fund routing
   to/through that exchange; it is NOT proof that the exchange entity itself is fraudulent.
4. Model Boundary: The offline Elliptic Random Forest model requires a full 165-feature vector
   and is not applied directly to raw on-chain addresses without compatible feature extraction.
"""

from .address import validate_address, canonicalize_address
from .tagpack import TagPack, TagPackParser
from .entity_registry import EntityRegistry
from .taint import calculate_haircut_taint, calculate_fifo_taint
from .graph import TransactionGraph, TxInput, TxOutput, Transaction
from .tracer import BlockchainTracer
from .engine import ExchangeIdentificationEngine

__all__ = [
    "validate_address",
    "canonicalize_address",
    "TagPack",
    "TagPackParser",
    "EntityRegistry",
    "calculate_haircut_taint",
    "calculate_fifo_taint",
    "TransactionGraph",
    "TxInput",
    "TxOutput",
    "Transaction",
    "BlockchainTracer",
    "ExchangeIdentificationEngine",
]
