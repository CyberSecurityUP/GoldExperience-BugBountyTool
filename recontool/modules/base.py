"""
Base module class for ReconTool

Provides the abstract base class that all recon modules inherit from,
with standardized interfaces for execution, logging, and output handling.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ..utils.logging import get_logger, log_tool_complete, log_tool_start
from ..utils.process import ToolResult, check_tool_exists, run_tool
from ..utils.scope import ScopeValidator
from ..utils.dedup import deduplicate_lines, merge_files
from ..utils.normalize import normalize_domain, normalize_url


@dataclass
class ModuleResult:
    """Result of a module execution."""
    module_name: str
    success: bool
    duration: float
    tool_results: List[ToolResult] = field(default_factory=list)
    output_files: Dict[str, Path] = field(default_factory=dict)
    stats: Dict[str, int] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    skipped_tools: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_tool_result(self, result: ToolResult) -> None:
        """Add a tool result and update stats."""
        self.tool_results.append(result)
        if result.success:
            self.stats[f"{result.tool_name}_count"] = result.result_count
        else:
            if result.tool_name not in self.skipped_tools:
                self.errors.append(f"{result.tool_name}: {result.error_message}")

    def get_total_results(self) -> int:
        """Get total result count across all tools."""
        return sum(
            r.result_count for r in self.tool_results if r.success
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "module_name": self.module_name,
            "success": self.success,
            "duration": round(self.duration, 2),
            "stats": self.stats,
            "findings": self.findings,
            "errors": self.errors,
            "skipped_tools": self.skipped_tools,
            "output_files": {k: str(v) for k, v in self.output_files.items()},
            "metadata": self.metadata,
        }


class BaseModule(ABC):
    """
    Abstract base class for all recon modules.

    Each module must implement:
    - name: Module identifier
    - tools: List of tools this module can use
    - run(): Execute the module
    """

    # Override in subclasses
    name: str = "base"
    description: str = "Base module"
    tools: List[str] = []
    output_dir: str = "output"

    def __init__(
        self,
        output_base: Path,
        scope: ScopeValidator,
        timeout: int = 300,
        rate_limit: float = 0.0,
        tool_options: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        """
        Initialize the module.

        Args:
            output_base: Base output directory
            scope: Scope validator for filtering results
            timeout: Default timeout for tools
            rate_limit: Delay between tool executions
            tool_options: Tool-specific options
        """
        self.output_base = output_base
        self.output_path = output_base / self.output_dir
        self.scope = scope
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.tool_options = tool_options or {}
        self.logger = get_logger(self.name)

        # Track available tools
        self._available_tools: Optional[Set[str]] = None

    @property
    def available_tools(self) -> Set[str]:
        """Get set of tools that are available on this system."""
        if self._available_tools is None:
            self._available_tools = {
                tool for tool in self.tools
                if check_tool_exists(tool)
            }
            missing = set(self.tools) - self._available_tools
            if missing:
                self.logger.warning(
                    f"Tools not available: {', '.join(missing)}"
                )
        return self._available_tools

    def ensure_output_dir(self) -> None:
        """Create output directory if it doesn't exist."""
        self.output_path.mkdir(parents=True, exist_ok=True)

    def get_output_file(self, name: str, subdir: Optional[str] = None) -> Path:
        """Get path for an output file."""
        if subdir:
            path = self.output_path / subdir
            path.mkdir(parents=True, exist_ok=True)
            return path / name
        return self.output_path / name

    def run_tool(
        self,
        tool_name: str,
        args: List[str],
        input_data: Optional[str] = None,
        input_file: Optional[Path] = None,
        output_file: Optional[Path] = None,
        timeout: Optional[int] = None,
    ) -> ToolResult:
        """
        Run a tool with logging and error handling.

        Args:
            tool_name: Name of the tool
            args: Command arguments
            input_data: Data to pass to stdin
            input_file: File for stdin
            output_file: File for stdout
            timeout: Override default timeout

        Returns:
            ToolResult with execution details
        """
        if tool_name not in self.available_tools:
            self.logger.warning(f"Tool {tool_name} not available, skipping")
            return ToolResult(
                tool_name=tool_name,
                success=False,
                returncode=-1,
                stdout="",
                stderr="Tool not available",
                duration=0.0,
                command=[tool_name] + args,
                error_message="Tool not available",
            )

        # Apply rate limiting
        if self.rate_limit > 0:
            time.sleep(self.rate_limit)

        # Get tool-specific options
        tool_opts = self.tool_options.get(tool_name, {})
        extra_args = tool_opts.get("extra_args", [])
        args = args + extra_args

        log_tool_start(self.logger, tool_name, str(args[:2]))

        result = run_tool(
            tool_name=tool_name,
            args=args,
            input_data=input_data,
            input_file=input_file,
            output_file=output_file,
            timeout=timeout or self.timeout,
            check_exists=False,  # Already checked
        )

        log_tool_complete(
            self.logger,
            tool_name,
            result.success,
            result.duration,
            result.result_count,
        )

        return result

    def filter_scope(self, items: List[str]) -> List[str]:
        """Filter a list of items to only in-scope ones."""
        return self.scope.filter_targets(items)

    def deduplicate(
        self,
        items: List[str],
        normalize_fn: Optional[callable] = None,
    ) -> List[str]:
        """Deduplicate a list of items."""
        return deduplicate_lines(items, normalize_fn=normalize_fn)

    def merge_outputs(
        self,
        output_files: List[Path],
        merged_file: Path,
        deduplicate: bool = True,
    ) -> int:
        """Merge multiple output files into one."""
        return merge_files(
            output_files,
            merged_file,
            deduplicate=deduplicate,
        )

    def read_input_file(self, path: Path) -> List[str]:
        """Read lines from an input file."""
        if not path.exists():
            self.logger.warning(f"Input file not found: {path}")
            return []
        return [
            line.strip()
            for line in path.read_text().strip().split("\n")
            if line.strip()
        ]

    def write_output_file(self, path: Path, items: List[str]) -> int:
        """Write items to an output file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(items))
        return len(items)

    def check_resume(self, output_file: Path) -> bool:
        """Check if output already exists for resuming."""
        if output_file.exists() and output_file.stat().st_size > 0:
            self.logger.info(f"Resuming: {output_file.name} already exists")
            return True
        return False

    @abstractmethod
    def run(
        self,
        targets: List[str],
        resume: bool = True,
        **kwargs,
    ) -> ModuleResult:
        """
        Execute the module.

        Args:
            targets: List of targets to process
            resume: Whether to skip if output exists
            **kwargs: Additional module-specific options

        Returns:
            ModuleResult with execution details
        """
        pass

    def get_stats(self) -> Dict[str, Any]:
        """Get module statistics for context generation."""
        return {
            "name": self.name,
            "description": self.description,
            "available_tools": list(self.available_tools),
            "missing_tools": list(set(self.tools) - self.available_tools),
        }


class PassiveModule(BaseModule):
    """Base class for passive recon modules (no active probing)."""

    def should_run(self, target_type: str) -> bool:
        """Check if this module should run for the target type."""
        return True


class ActiveModule(BaseModule):
    """Base class for active recon modules (sends requests to targets)."""

    def should_run(self, target_type: str) -> bool:
        """Check if this module should run for the target type."""
        # Active modules typically need HTTP targets
        return target_type in ["domain", "url"]
