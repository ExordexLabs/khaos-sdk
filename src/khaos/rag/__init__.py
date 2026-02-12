"""RAG (Retrieval-Augmented Generation) fault injection module.

Provides specialized faults for testing agent resilience against:
- Retrieval poisoning attacks
- Context window overflow attacks
- Document instruction injection
"""

from khaos.rag.faults import (
    RAGFaultType,
    RAGRetrievalPoisoningConfig,
    RAGContextOverflowConfig,
    RAGInstructionInjectionConfig,
    apply_rag_fault,
    enable_rag_fault_shim,
)

__all__ = [
    "RAGFaultType",
    "RAGRetrievalPoisoningConfig",
    "RAGContextOverflowConfig",
    "RAGInstructionInjectionConfig",
    "apply_rag_fault",
    "enable_rag_fault_shim",
]
