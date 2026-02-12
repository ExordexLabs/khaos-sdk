"""Custom fault plugin system for extensible fault injection.

This module provides a plugin architecture that allows users to define
custom fault types beyond the built-in ones. Plugins can be registered
via decorator or programmatically.

Example usage:

    from khaos.engine.fault_plugins import FaultPlugin, register_fault

    @register_fault("degraded_ml_model")
    class DegradedMLModelFault(FaultPlugin):
        '''Simulates a degraded ML model response.'''

        async def inject(self, config: dict) -> dict:
            degradation_level = config.get("level", 0.5)
            # Custom fault logic here
            return {
                "injected": True,
                "degradation_level": degradation_level,
                "outcome": "degraded_ml_model",
            }

    # In scenario YAML:
    # faults:
    #   - type: degraded_ml_model
    #     config:
    #       level: 0.8
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any
from collections.abc import Awaitable, Callable

from .scheduler import SeededScheduler

class FaultPlugin(ABC):
    """Base class for custom fault plugins.
    
    Subclass this to create custom fault types. The `inject` method
    will be called when the fault is triggered during a chaos run.
    
    Attributes:
        name: The fault type identifier (set automatically by @register_fault)
        scheduler: The seeded scheduler for deterministic timing
    """
    
    name: str = ""
    scheduler: SeededScheduler | None = None
    
    def __init__(self, scheduler: SeededScheduler | None = None):
        self.scheduler = scheduler
    
    @abstractmethod
    async def inject(self, config: dict[str, Any]) -> dict[str, Any]:
        """Execute the fault injection.
        
        Args:
            config: Configuration dict from the scenario YAML
            
        Returns:
            Dict containing fault outcome metadata. Should include
            an "outcome" key describing what happened.
        """
        pass
    
    async def sleep(self, seconds: float, jitter: float = 0.0) -> None:
        """Sleep with optional jitter, using the seeded scheduler if available."""
        if self.scheduler:
            await self.scheduler.sleep(seconds, jitter=jitter)
        else:
            await asyncio.sleep(seconds)
    
    def get_config_value(
        self,
        config: dict[str, Any],
        key: str,
        default: Any = None,
        cast: Callable[[Any], Any] | None = None,
    ) -> Any:
        """Safely extract and optionally cast a config value."""
        value = config.get(key, default)
        if cast is not None and value is not None:
            try:
                return cast(value)
            except (ValueError, TypeError):
                return default
        return value

# Global registry for custom fault plugins
_PLUGIN_REGISTRY: dict[str, type[FaultPlugin]] = {}

def register_fault(fault_type: str) -> Callable[[type[FaultPlugin]], type[FaultPlugin]]:
    """Decorator to register a custom fault plugin.
    
    Args:
        fault_type: The identifier used in scenario YAML (e.g., "degraded_ml_model")
        
    Returns:
        Decorator function
        
    Example:
        @register_fault("my_custom_fault")
        class MyCustomFault(FaultPlugin):
            async def inject(self, config: dict) -> dict:
                return {"outcome": "my_custom_fault"}
    """
    def decorator(cls: type[FaultPlugin]) -> type[FaultPlugin]:
        if not issubclass(cls, FaultPlugin):
            raise TypeError(f"{cls.__name__} must be a subclass of FaultPlugin")
        cls.name = fault_type
        _PLUGIN_REGISTRY[fault_type] = cls
        return cls
    return decorator

def register_fault_class(fault_type: str, cls: type[FaultPlugin]) -> None:
    """Programmatically register a fault plugin class.
    
    Args:
        fault_type: The identifier used in scenario YAML
        cls: The FaultPlugin subclass to register
    """
    if not issubclass(cls, FaultPlugin):
        raise TypeError(f"{cls.__name__} must be a subclass of FaultPlugin")
    cls.name = fault_type
    _PLUGIN_REGISTRY[fault_type] = cls

def unregister_fault(fault_type: str) -> bool:
    """Remove a fault plugin from the registry.
    
    Args:
        fault_type: The fault type identifier to remove
        
    Returns:
        True if the fault was removed, False if it wasn't registered
    """
    if fault_type in _PLUGIN_REGISTRY:
        del _PLUGIN_REGISTRY[fault_type]
        return True
    return False

def get_registered_faults() -> dict[str, type[FaultPlugin]]:
    """Get a copy of all registered custom fault plugins."""
    return dict(_PLUGIN_REGISTRY)

def is_custom_fault(fault_type: str) -> bool:
    """Check if a fault type is a registered custom plugin."""
    return fault_type in _PLUGIN_REGISTRY

def get_plugin_class(fault_type: str) -> type[FaultPlugin] | None:
    """Get the plugin class for a fault type, if registered."""
    return _PLUGIN_REGISTRY.get(fault_type)

async def execute_custom_fault(
    fault_type: str,
    config: dict[str, Any],
    scheduler: SeededScheduler | None = None,
) -> dict[str, Any]:
    """Execute a custom fault plugin.
    
    Args:
        fault_type: The fault type identifier
        config: Configuration dict from the scenario
        scheduler: Optional seeded scheduler for deterministic timing
        
    Returns:
        Fault outcome metadata from the plugin
        
    Raises:
        KeyError: If the fault type is not registered
        RuntimeError: If the plugin execution fails
    """
    if fault_type not in _PLUGIN_REGISTRY:
        raise KeyError(f"Custom fault '{fault_type}' is not registered")
    
    plugin_cls = _PLUGIN_REGISTRY[fault_type]
    plugin = plugin_cls(scheduler=scheduler)
    
    try:
        result = await plugin.inject(config)
        # Ensure outcome is set
        if "outcome" not in result:
            result["outcome"] = fault_type
        return result
    except Exception as e:
        raise RuntimeError(f"Custom fault '{fault_type}' failed: {e}") from e

def create_fault_handler(fault_type: str) -> Callable[
    [dict[str, Any], SeededScheduler], Awaitable[dict[str, Any]]
]:
    """Create a fault handler function compatible with FAULT_HANDLERS.
    
    This allows custom plugins to be used alongside built-in faults.
    
    Args:
        fault_type: The registered custom fault type
        
    Returns:
        Async handler function matching the FaultHandler signature
    """
    async def handler(config: dict[str, Any], scheduler: SeededScheduler) -> dict[str, Any]:
        return await execute_custom_fault(fault_type, config, scheduler)
    return handler

# ============================================================================
# Built-in Example Plugins (can be used as templates)
# ============================================================================

@register_fault("custom_delay")
class CustomDelayFault(FaultPlugin):
    """Simple delay fault - useful as a template for custom faults."""
    
    async def inject(self, config: dict[str, Any]) -> dict[str, Any]:
        delay_ms = self.get_config_value(config, "delay_ms", 100, float)
        jitter_ms = self.get_config_value(config, "jitter_ms", 0, float)
        
        await self.sleep(delay_ms / 1000.0, jitter=jitter_ms / 1000.0)
        
        return {
            "delay_ms": delay_ms,
            "jitter_ms": jitter_ms,
            "outcome": "custom_delay",
        }

@register_fault("data_corruption")
class DataCorruptionFault(FaultPlugin):
    """Simulates corrupted data in tool responses."""
    
    async def inject(self, config: dict[str, Any]) -> dict[str, Any]:
        corruption_type = self.get_config_value(config, "corruption_type", "truncate", str)
        severity = self.get_config_value(config, "severity", 0.5, float)
        field = self.get_config_value(config, "field", None, str)
        
        await self.sleep(self.get_config_value(config, "delay_ms", 0, float) / 1000.0)
        
        return {
            "corruption_type": corruption_type,
            "severity": severity,
            "field": field,
            "outcome": "data_corruption",
        }

@register_fault("rate_limit")
class RateLimitFault(FaultPlugin):
    """Simulates API rate limiting (429 responses)."""
    
    async def inject(self, config: dict[str, Any]) -> dict[str, Any]:
        retry_after = self.get_config_value(config, "retry_after_seconds", 60, int)
        limit = self.get_config_value(config, "limit", 100, int)
        remaining = self.get_config_value(config, "remaining", 0, int)
        
        await self.sleep(self.get_config_value(config, "delay_ms", 0, float) / 1000.0)
        
        return {
            "status_code": 429,
            "retry_after_seconds": retry_after,
            "rate_limit": limit,
            "rate_remaining": remaining,
            "outcome": "rate_limit",
        }

@register_fault("partial_response")
class PartialResponseFault(FaultPlugin):
    """Simulates incomplete/truncated responses."""
    
    async def inject(self, config: dict[str, Any]) -> dict[str, Any]:
        truncate_at = self.get_config_value(config, "truncate_at_percent", 50, float)
        include_error = self.get_config_value(config, "include_error", False, bool)
        
        await self.sleep(self.get_config_value(config, "delay_ms", 0, float) / 1000.0)
        
        return {
            "truncate_at_percent": truncate_at,
            "include_error": include_error,
            "outcome": "partial_response",
        }
