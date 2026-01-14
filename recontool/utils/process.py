"""
Process execution utilities for ReconTool

Provides safe subprocess execution with timeouts, error handling,
and output capture.
"""

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

from .logging import get_logger

logger = get_logger("process")


@dataclass
class ToolResult:
    """Result of a tool execution."""
    tool_name: str
    success: bool
    returncode: int
    stdout: str
    stderr: str
    duration: float
    command: List[str]
    output_file: Optional[Path] = None
    result_count: int = 0
    error_message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Parse result count from output if not set."""
        if self.success and self.result_count == 0 and self.stdout:
            # Count non-empty lines as results
            self.result_count = len([
                line for line in self.stdout.strip().split("\n")
                if line.strip()
            ])


def check_tool_exists(tool_name: str) -> bool:
    """
    Check if a tool is available in the system PATH.

    Args:
        tool_name: Name of the tool to check

    Returns:
        True if tool exists, False otherwise
    """
    return shutil.which(tool_name) is not None


def get_tool_path(tool_name: str) -> Optional[str]:
    """
    Get the full path to a tool.

    Args:
        tool_name: Name of the tool

    Returns:
        Full path to the tool or None if not found
    """
    return shutil.which(tool_name)


def run_tool(
    tool_name: str,
    args: List[str],
    input_data: Optional[str] = None,
    input_file: Optional[Path] = None,
    output_file: Optional[Path] = None,
    timeout: int = 300,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[Path] = None,
    check_exists: bool = True,
) -> ToolResult:
    """
    Run an external tool safely with timeout and error handling.

    Args:
        tool_name: Name of the tool to run
        args: List of command arguments
        input_data: String data to pass to stdin
        input_file: File to use as stdin
        output_file: File to write stdout to
        timeout: Maximum execution time in seconds
        env: Additional environment variables
        cwd: Working directory for the command
        check_exists: Whether to check if tool exists first

    Returns:
        ToolResult with execution details
    """
    start_time = time.time()

    # Check if tool exists
    if check_exists and not check_tool_exists(tool_name):
        logger.warning(f"Tool '{tool_name}' not found in PATH, skipping")
        return ToolResult(
            tool_name=tool_name,
            success=False,
            returncode=-1,
            stdout="",
            stderr=f"Tool '{tool_name}' not found",
            duration=0.0,
            command=[tool_name] + args,
            error_message=f"Tool '{tool_name}' not found in PATH",
        )

    # Build command
    cmd = [tool_name] + args
    logger.debug(f"Running command: {' '.join(cmd)}")

    # Prepare stdin
    stdin_data = None
    stdin_handle = None

    if input_data:
        stdin_data = input_data
    elif input_file and input_file.exists():
        stdin_handle = subprocess.PIPE
        stdin_data = input_file.read_text()

    # Prepare environment
    process_env = None
    if env:
        import os
        process_env = os.environ.copy()
        process_env.update(env)

    try:
        # Run the command
        result = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=process_env,
            cwd=cwd,
        )

        duration = time.time() - start_time
        success = result.returncode == 0

        # Write output to file if specified
        if output_file and result.stdout:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(result.stdout)

        tool_result = ToolResult(
            tool_name=tool_name,
            success=success,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            duration=duration,
            command=cmd,
            output_file=output_file,
        )

        if not success and result.stderr:
            tool_result.error_message = result.stderr[:500]
            logger.warning(f"{tool_name} exited with code {result.returncode}")
            logger.debug(f"Stderr: {result.stderr[:200]}")

        return tool_result

    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        logger.error(f"{tool_name} timed out after {timeout}s")
        return ToolResult(
            tool_name=tool_name,
            success=False,
            returncode=-1,
            stdout="",
            stderr=f"Command timed out after {timeout}s",
            duration=duration,
            command=cmd,
            error_message=f"Timeout after {timeout}s",
        )

    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"Error running {tool_name}: {str(e)}")
        return ToolResult(
            tool_name=tool_name,
            success=False,
            returncode=-1,
            stdout="",
            stderr=str(e),
            duration=duration,
            command=cmd,
            error_message=str(e),
        )


def run_tool_with_file_input(
    tool_name: str,
    args: List[str],
    input_file: Path,
    output_file: Optional[Path] = None,
    timeout: int = 300,
    input_flag: str = "-l",
) -> ToolResult:
    """
    Run a tool with file input using a flag.

    Many tools accept input via a file flag like -l or -list.

    Args:
        tool_name: Name of the tool
        args: Additional arguments
        input_file: Input file path
        output_file: Output file path
        timeout: Timeout in seconds
        input_flag: Flag to use for input file (-l, -list, etc.)

    Returns:
        ToolResult with execution details
    """
    full_args = args + [input_flag, str(input_file)]
    return run_tool(
        tool_name=tool_name,
        args=full_args,
        output_file=output_file,
        timeout=timeout,
    )


def run_piped_tools(
    tools: List[tuple],
    timeout: int = 300,
) -> ToolResult:
    """
    Run multiple tools in a pipe.

    Args:
        tools: List of (tool_name, args) tuples
        timeout: Total timeout for the pipeline

    Returns:
        ToolResult from the final tool
    """
    if not tools:
        return ToolResult(
            tool_name="pipeline",
            success=False,
            returncode=-1,
            stdout="",
            stderr="No tools specified",
            duration=0.0,
            command=[],
            error_message="No tools specified",
        )

    start_time = time.time()
    current_input = None

    for i, (tool_name, args) in enumerate(tools):
        is_last = i == len(tools) - 1
        remaining_timeout = max(1, timeout - (time.time() - start_time))

        result = run_tool(
            tool_name=tool_name,
            args=args,
            input_data=current_input,
            timeout=int(remaining_timeout),
        )

        if not result.success:
            return result

        current_input = result.stdout

        if is_last:
            result.duration = time.time() - start_time
            result.command = [f"{t[0]} {' '.join(t[1])}" for t in tools]
            return result

    # Should not reach here
    return result
