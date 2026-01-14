"""
ReconTool - Autonomous Reconnaissance Framework
================================================

A production-grade, modular autonomous reconnaissance script for
offensive security operations (bug bounty, red team, pentesting).

This framework is designed to:
- Run ALL recon tools autonomously
- Manage scope enforcement
- Organize outputs by category
- Generate structured context for LLM consumption
- Support parallel execution for speed

The LLM consuming this output should NEVER execute tools directly.
"""

__version__ = "1.0.0"
__author__ = "ReconTool"

from .config import Config
from .runner import ReconRunner

__all__ = ["Config", "ReconRunner", "__version__"]
