"""Artifact management for Khaos runs.

This module provides unified artifact handling across all execution modes:
- Scenario mode
- Pack/CI mode
- Observe mode

Each run produces a manifest.json that captures reproducibility and provenance
information, enabling reliable comparison and regression detection.
"""

from .manifest import RunManifest, write_manifest, load_manifest, generate_run_id

__all__ = ["RunManifest", "write_manifest", "load_manifest", "generate_run_id"]
