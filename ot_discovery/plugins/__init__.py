"""Plugin system for OT Discovery."""

from .base import PluginBase, PluginMatchResult
from .manager import PluginManager
from .manufacturers import create_default_plugin_manager

__all__ = ["PluginBase", "PluginMatchResult", "PluginManager", "create_default_plugin_manager"]