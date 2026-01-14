"""
Deduplication utilities for ReconTool

Provides functions to deduplicate lines, URLs, and merge files
while preserving order and handling large datasets efficiently.
"""

from pathlib import Path
from typing import Callable, List, Optional, Set

from .logging import get_logger
from .normalize import normalize_url, normalize_domain

logger = get_logger("dedup")


def deduplicate_lines(
    lines: List[str],
    normalize_fn: Optional[Callable[[str], str]] = None,
    case_sensitive: bool = False,
) -> List[str]:
    """
    Deduplicate a list of lines while preserving order.

    Args:
        lines: List of lines to deduplicate
        normalize_fn: Optional function to normalize lines before comparison
        case_sensitive: Whether comparison should be case-sensitive

    Returns:
        Deduplicated list maintaining original order
    """
    seen: Set[str] = set()
    result: List[str] = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Apply normalization if provided
        if normalize_fn:
            key = normalize_fn(line)
        else:
            key = line

        # Handle case sensitivity
        if not case_sensitive:
            key = key.lower()

        if key not in seen:
            seen.add(key)
            result.append(line)

    return result


def deduplicate_urls(urls: List[str]) -> List[str]:
    """
    Deduplicate URLs using URL normalization.

    Args:
        urls: List of URLs to deduplicate

    Returns:
        Deduplicated list of URLs
    """
    return deduplicate_lines(urls, normalize_fn=normalize_url)


def deduplicate_domains(domains: List[str]) -> List[str]:
    """
    Deduplicate domains using domain normalization.

    Args:
        domains: List of domains to deduplicate

    Returns:
        Deduplicated list of domains
    """
    return deduplicate_lines(domains, normalize_fn=normalize_domain)


def deduplicate_file(
    input_file: Path,
    output_file: Optional[Path] = None,
    normalize_fn: Optional[Callable[[str], str]] = None,
) -> int:
    """
    Deduplicate lines in a file.

    Args:
        input_file: File to deduplicate
        output_file: Output file (defaults to input_file)
        normalize_fn: Optional normalization function

    Returns:
        Number of unique lines
    """
    if not input_file.exists():
        logger.warning(f"Input file {input_file} does not exist")
        return 0

    lines = input_file.read_text().strip().split("\n")
    original_count = len(lines)

    deduped = deduplicate_lines(lines, normalize_fn=normalize_fn)
    unique_count = len(deduped)

    if output_file is None:
        output_file = input_file

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("\n".join(deduped))

    removed = original_count - unique_count
    if removed > 0:
        logger.debug(f"Removed {removed} duplicates from {input_file.name}")

    return unique_count


def merge_files(
    input_files: List[Path],
    output_file: Path,
    deduplicate: bool = True,
    normalize_fn: Optional[Callable[[str], str]] = None,
) -> int:
    """
    Merge multiple files into one, optionally deduplicating.

    Args:
        input_files: List of files to merge
        output_file: Output file path
        deduplicate: Whether to deduplicate the merged output
        normalize_fn: Optional normalization function for deduplication

    Returns:
        Number of lines in the output file
    """
    all_lines: List[str] = []

    for input_file in input_files:
        if not input_file.exists():
            logger.debug(f"Skipping non-existent file: {input_file}")
            continue

        lines = input_file.read_text().strip().split("\n")
        all_lines.extend(line for line in lines if line.strip())

    if deduplicate:
        all_lines = deduplicate_lines(all_lines, normalize_fn=normalize_fn)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("\n".join(all_lines))

    logger.info(f"Merged {len(input_files)} files into {output_file.name} ({len(all_lines)} lines)")
    return len(all_lines)


def merge_and_sort(
    input_files: List[Path],
    output_file: Path,
    deduplicate: bool = True,
    reverse: bool = False,
) -> int:
    """
    Merge and sort multiple files.

    Args:
        input_files: List of files to merge
        output_file: Output file path
        deduplicate: Whether to deduplicate
        reverse: Whether to reverse sort

    Returns:
        Number of lines in output
    """
    all_lines: List[str] = []

    for input_file in input_files:
        if not input_file.exists():
            continue
        lines = input_file.read_text().strip().split("\n")
        all_lines.extend(line.strip() for line in lines if line.strip())

    if deduplicate:
        all_lines = list(set(all_lines))

    all_lines.sort(reverse=reverse)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("\n".join(all_lines))

    return len(all_lines)


def subtract_files(
    main_file: Path,
    subtract_file: Path,
    output_file: Path,
    normalize_fn: Optional[Callable[[str], str]] = None,
) -> int:
    """
    Subtract lines in one file from another.

    Args:
        main_file: File containing lines to keep
        subtract_file: File containing lines to remove
        output_file: Output file path
        normalize_fn: Optional normalization function

    Returns:
        Number of remaining lines
    """
    if not main_file.exists():
        logger.warning(f"Main file {main_file} does not exist")
        return 0

    main_lines = main_file.read_text().strip().split("\n")

    subtract_set: Set[str] = set()
    if subtract_file.exists():
        subtract_lines = subtract_file.read_text().strip().split("\n")
        for line in subtract_lines:
            if normalize_fn:
                subtract_set.add(normalize_fn(line.strip()).lower())
            else:
                subtract_set.add(line.strip().lower())

    result: List[str] = []
    for line in main_lines:
        line = line.strip()
        if not line:
            continue
        key = normalize_fn(line).lower() if normalize_fn else line.lower()
        if key not in subtract_set:
            result.append(line)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("\n".join(result))

    removed = len(main_lines) - len(result)
    logger.debug(f"Subtracted {removed} lines from {main_file.name}")

    return len(result)


def count_lines(file_path: Path) -> int:
    """
    Count non-empty lines in a file.

    Args:
        file_path: Path to file

    Returns:
        Number of non-empty lines
    """
    if not file_path.exists():
        return 0

    return sum(
        1 for line in file_path.read_text().split("\n")
        if line.strip()
    )


def split_file(
    input_file: Path,
    output_dir: Path,
    lines_per_file: int = 1000,
    prefix: str = "chunk_",
) -> List[Path]:
    """
    Split a large file into smaller chunks.

    Args:
        input_file: File to split
        output_dir: Directory to write chunks
        lines_per_file: Maximum lines per chunk
        prefix: Prefix for chunk filenames

    Returns:
        List of chunk file paths
    """
    if not input_file.exists():
        return []

    output_dir.mkdir(parents=True, exist_ok=True)

    lines = input_file.read_text().strip().split("\n")
    chunks: List[Path] = []

    for i in range(0, len(lines), lines_per_file):
        chunk_lines = lines[i:i + lines_per_file]
        chunk_file = output_dir / f"{prefix}{i // lines_per_file:04d}.txt"
        chunk_file.write_text("\n".join(chunk_lines))
        chunks.append(chunk_file)

    logger.info(f"Split {input_file.name} into {len(chunks)} chunks")
    return chunks
