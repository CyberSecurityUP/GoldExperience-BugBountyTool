"""
Logging utilities for ReconTool

Provides per-module logging with rotation, colored output, and
centralized log management.
"""

import logging
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

# ANSI color codes for terminal output
COLORS = {
    "DEBUG": "\033[36m",     # Cyan
    "INFO": "\033[32m",      # Green
    "WARNING": "\033[33m",   # Yellow
    "ERROR": "\033[31m",     # Red
    "CRITICAL": "\033[35m",  # Magenta
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for terminal output."""

    def format(self, record: logging.LogRecord) -> str:
        # Add color to the level name
        levelname = record.levelname
        if levelname in COLORS:
            record.levelname = f"{COLORS[levelname]}{levelname}{COLORS['RESET']}"

        # Add module name in bold if present
        if hasattr(record, "module_name"):
            record.module_name = f"{COLORS['BOLD']}[{record.module_name}]{COLORS['RESET']}"

        return super().format(record)


class PlainFormatter(logging.Formatter):
    """Plain formatter for file output (no colors)."""
    pass


class ModuleLogger(logging.LoggerAdapter):
    """Logger adapter that adds module context to log messages."""

    def process(self, msg: str, kwargs: dict) -> tuple:
        kwargs.setdefault("extra", {})
        kwargs["extra"]["module_name"] = self.extra.get("module_name", "main")
        return msg, kwargs


# Global logger cache
_loggers: dict = {}
_log_dir: Optional[Path] = None


def setup_logging(
    log_dir: Path,
    level: str = "INFO",
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
) -> None:
    """
    Initialize the logging system.

    Args:
        log_dir: Directory to store log files
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        max_bytes: Maximum size of each log file before rotation
        backup_count: Number of backup files to keep
    """
    global _log_dir
    _log_dir = Path(log_dir)
    _log_dir.mkdir(parents=True, exist_ok=True)

    # Get numeric level
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Configure root logger
    root_logger = logging.getLogger("recontool")
    root_logger.setLevel(numeric_level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_format = "%(asctime)s %(levelname)s %(module_name)s %(message)s"
    console_handler.setFormatter(ColoredFormatter(console_format, datefmt="%H:%M:%S"))
    root_logger.addHandler(console_handler)

    # Main log file handler with rotation
    main_log_file = _log_dir / "recon.log"
    file_handler = RotatingFileHandler(
        main_log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
    )
    file_handler.setLevel(numeric_level)
    file_format = "%(asctime)s [%(levelname)s] [%(module_name)s] %(message)s"
    file_handler.setFormatter(PlainFormatter(file_format))
    root_logger.addHandler(file_handler)

    # Error log file (only errors and above)
    error_log_file = _log_dir / "errors.log"
    error_handler = RotatingFileHandler(
        error_log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(PlainFormatter(file_format))
    root_logger.addHandler(error_handler)


def get_logger(module_name: str = "main") -> ModuleLogger:
    """
    Get a logger instance for a specific module.

    Args:
        module_name: Name of the module requesting the logger

    Returns:
        ModuleLogger instance configured for the module
    """
    global _loggers, _log_dir

    if module_name in _loggers:
        return _loggers[module_name]

    # Get base logger
    base_logger = logging.getLogger("recontool")

    # Create module-specific logger adapter
    logger = ModuleLogger(base_logger, {"module_name": module_name})

    # If log dir is set, create module-specific log file
    if _log_dir is not None:
        module_log_file = _log_dir / f"{module_name}.log"
        module_handler = RotatingFileHandler(
            module_log_file,
            maxBytes=5 * 1024 * 1024,  # 5MB per module
            backupCount=3,
        )
        module_handler.setLevel(logging.DEBUG)
        file_format = "%(asctime)s [%(levelname)s] %(message)s"
        module_handler.setFormatter(PlainFormatter(file_format))

        # Add handler to base logger if not already present
        handler_exists = any(
            isinstance(h, RotatingFileHandler) and
            getattr(h, "baseFilename", "").endswith(f"{module_name}.log")
            for h in base_logger.handlers
        )
        if not handler_exists:
            base_logger.addHandler(module_handler)

    _loggers[module_name] = logger
    return logger


def log_banner(logger: ModuleLogger, text: str) -> None:
    """Log a formatted banner message."""
    border = "=" * 60
    logger.info(border)
    logger.info(f"  {text}")
    logger.info(border)


def log_tool_start(logger: ModuleLogger, tool_name: str, target: str) -> None:
    """Log the start of a tool execution."""
    logger.info(f"Starting {tool_name} against {target}")


def log_tool_complete(
    logger: ModuleLogger,
    tool_name: str,
    success: bool,
    duration: float,
    result_count: int = 0,
) -> None:
    """Log the completion of a tool execution."""
    status = "completed" if success else "failed"
    logger.info(
        f"{tool_name} {status} in {duration:.2f}s "
        f"({result_count} results)"
    )
