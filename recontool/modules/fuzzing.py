"""
Fuzzing Module - Enhanced Version

Directory and file fuzzing for content discovery:
- ffuf (primary)
- feroxbuster (recursive)

Output structure:
  fuzzing/
    ├── raw/
    │   ├── ffuf/
    │   │   ├── target1_ffuf.json
    │   │   └── target2_ffuf.json
    │   └── feroxbuster/
    ├── all_findings.txt
    ├── by_status/
    │   ├── 200.txt
    │   ├── 301.txt
    │   ├── 403.txt
    │   └── ...
    ├── by_type/
    │   ├── sensitive.txt (.git, .env, config)
    │   ├── api.txt (/api/, /v1/, etc)
    │   ├── backup.txt (.bak, .old, .zip)
    │   ├── admin.txt
    │   └── interesting.txt
    └── fuzzing_summary.json
"""

import json
import re
import time
from pathlib import Path
from typing import List, Optional, Dict, Set
from collections import defaultdict
from urllib.parse import urlparse

from .base import ActiveModule, ModuleResult
from ..utils.process import ToolResult, check_tool_exists
from ..utils.dedup import merge_files, deduplicate_lines


class FuzzingModule(ActiveModule):
    """Enhanced directory and file fuzzing with categorized output."""

    name = "fuzzing"
    description = "Discover hidden directories, files, and endpoints through fuzzing"
    tools = ["ffuf", "feroxbuster"]
    output_dir = "fuzzing"

    # Default wordlist paths (common locations)
    DEFAULT_WORDLISTS = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/opt/wordlists/common.txt",
    ]

    # Path categorization patterns
    PATH_CATEGORIES = {
        "sensitive": [".git", ".env", ".svn", ".htaccess", ".htpasswd", "config", "credentials",
                     "secret", "private", ".aws", ".ssh", "id_rsa", "wp-config"],
        "backup": [".bak", ".backup", ".old", ".orig", ".copy", ".zip", ".tar", ".gz",
                  ".sql", ".dump", "backup", ".swp", "~"],
        "api": ["/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql", "/json/", "/xml/",
               "/swagger", "/api-docs", "/openapi"],
        "admin": ["admin", "administrator", "manager", "dashboard", "panel", "console",
                 "control", "manage", "backend", "cms"],
        "dev": ["debug", "test", "dev", "staging", "beta", "internal", "development",
               "phpinfo", "info.php", "server-status"],
        "upload": ["upload", "uploads", "file", "files", "media", "attachments",
                  "documents", "images", "assets"],
    }

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        wordlist: Optional[Path] = None,
        threads: int = 40,
        extensions: str = "",
        **kwargs,
    ) -> ModuleResult:
        """
        Run fuzzing against target URLs.

        Args:
            targets: List of base URLs to fuzz
            resume: Skip if output exists
            input_file: File containing URLs
            wordlist: Custom wordlist path
            threads: Number of concurrent threads
            extensions: File extensions to fuzz (e.g., "php,html,js")

        Returns:
            ModuleResult with categorized discovered paths
        """
        start_time = time.time()
        self.ensure_output_dir()

        result = ModuleResult(
            module_name=self.name,
            success=True,
            duration=0.0,
        )

        # Create directories
        raw_dir = self.output_path / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        ffuf_dir = raw_dir / "ffuf"
        ffuf_dir.mkdir(parents=True, exist_ok=True)
        ferox_dir = raw_dir / "feroxbuster"
        ferox_dir.mkdir(parents=True, exist_ok=True)
        status_dir = self.output_path / "by_status"
        status_dir.mkdir(parents=True, exist_ok=True)
        type_dir = self.output_path / "by_type"
        type_dir.mkdir(parents=True, exist_ok=True)

        # Load targets
        if input_file and input_file.exists():
            targets = self.read_input_file(input_file)

        if not targets:
            self.logger.warning("No targets provided for fuzzing")
            result.duration = time.time() - start_time
            return result

        # Filter and deduplicate
        targets = self.filter_scope(targets)
        targets = list(set(targets))

        # Limit targets for fuzzing (can be resource intensive)
        if len(targets) > 30:
            self.logger.warning(f"Limiting to 30 targets (had {len(targets)})")
            targets = targets[:30]

        self.logger.info(f"{'='*50}")
        self.logger.info(f"Fuzzing {len(targets)} targets")
        self.logger.info(f"{'='*50}")

        # Find wordlist
        wl_path = self._find_wordlist(wordlist)
        if not wl_path:
            self.logger.error("No wordlist available for fuzzing")
            result.errors.append("No wordlist found")
            result.success = False
            result.duration = time.time() - start_time
            return result

        self.logger.info(f"Using wordlist: {wl_path}")

        # Output files
        all_findings_file = self.output_path / "all_findings.txt"

        if resume and all_findings_file.exists() and all_findings_file.stat().st_size > 0:
            self.logger.info("Resuming: Using existing fuzzing results")
            result.duration = time.time() - start_time
            return result

        # Data structures for aggregation
        all_findings: List[Dict] = []

        for target in targets:
            target_name = self._sanitize_target_name(target)
            self.logger.info(f"Fuzzing: {target}")

            # Run ffuf
            if check_tool_exists("ffuf"):
                ffuf_json = ffuf_dir / f"{target_name}_ffuf.json"
                ffuf_txt = ffuf_dir / f"{target_name}_ffuf.txt"
                ffuf_result = self._run_ffuf(
                    target, wl_path, ffuf_txt, ffuf_json, threads, extensions
                )
                result.add_tool_result(ffuf_result)
                if ffuf_result.success and ffuf_json.exists():
                    findings = self._parse_ffuf_json(ffuf_json, target)
                    all_findings.extend(findings)
                    self.logger.info(f"  ffuf: {len(findings)} paths found")

            # Run feroxbuster
            if check_tool_exists("feroxbuster"):
                ferox_out = ferox_dir / f"{target_name}_feroxbuster.txt"
                ferox_result = self._run_feroxbuster(
                    target, wl_path, ferox_out, threads, extensions
                )
                result.add_tool_result(ferox_result)
                if ferox_result.success and ferox_out.exists():
                    findings = self._parse_feroxbuster(ferox_out, target)
                    all_findings.extend(findings)
                    self.logger.info(f"  feroxbuster: {len(findings)} paths found")

        # Deduplicate and categorize
        if all_findings:
            unique_findings = self._deduplicate_findings(all_findings)
            self._categorize_and_write(
                unique_findings, all_findings_file, status_dir, type_dir, result
            )

        # Save JSON summary
        self._save_json_summary(result)

        result.duration = time.time() - start_time
        return result

    def _find_wordlist(self, custom_path: Optional[Path]) -> Optional[Path]:
        """Find an available wordlist."""
        if custom_path and custom_path.exists():
            return custom_path

        for wl in self.DEFAULT_WORDLISTS:
            path = Path(wl)
            if path.exists():
                return path

        return None

    def _sanitize_target_name(self, target: str) -> str:
        """Create a safe filename from a target URL."""
        parsed = urlparse(target)
        name = parsed.netloc or parsed.path
        name = re.sub(r"[^a-zA-Z0-9.-]", "_", name)
        return name[:50]

    def _run_ffuf(
        self,
        target: str,
        wordlist: Path,
        output_file: Path,
        json_file: Path,
        threads: int,
        extensions: str,
    ) -> ToolResult:
        """Run ffuf for directory fuzzing."""
        # Ensure target has FUZZ keyword
        fuzz_url = target.rstrip("/") + "/FUZZ"

        args = [
            "-u", fuzz_url,
            "-w", str(wordlist),
            "-o", str(json_file),
            "-of", "json",
            "-t", str(threads),
            "-mc", "200,201,202,204,301,302,307,308,401,403,405,500",
            "-ac",  # Auto-calibrate filtering
            "-s",   # Silent mode
            "-timeout", "10",
            "-r",   # Follow redirects
        ]

        if extensions:
            args.extend(["-e", extensions])

        result = self.run_tool("ffuf", args, timeout=900)

        # Convert JSON to text output
        if result.success and json_file.exists():
            self._ffuf_json_to_txt(json_file, output_file)

        return result

    def _ffuf_json_to_txt(self, json_file: Path, txt_file: Path) -> None:
        """Convert ffuf JSON output to text."""
        try:
            data = json.loads(json_file.read_text())
            results = data.get("results", [])
            lines = []
            for r in results:
                url = r.get("url", "")
                status = r.get("status", "")
                length = r.get("length", "")
                lines.append(f"{url} [{status}] [{length}]")
            txt_file.write_text("\n".join(lines))
        except Exception as e:
            self.logger.error(f"Error converting ffuf JSON: {e}")

    def _run_feroxbuster(
        self,
        target: str,
        wordlist: Path,
        output_file: Path,
        threads: int,
        extensions: str,
    ) -> ToolResult:
        """Run feroxbuster for recursive directory fuzzing."""
        args = [
            "-u", target,
            "-w", str(wordlist),
            "-o", str(output_file),
            "-t", str(threads),
            "-d", "2",  # Depth limit
            "--silent",
            "-k",  # Ignore TLS errors
            "--timeout", "10",
            "-s", "200,201,202,204,301,302,307,308,401,403,405,500",
            "-n",  # No recursion by default (depth handles this)
        ]

        if extensions:
            args.extend(["-x", extensions])

        return self.run_tool("feroxbuster", args, timeout=900)

    def _parse_ffuf_json(self, json_file: Path, target: str) -> List[Dict]:
        """Parse ffuf JSON for findings."""
        findings = []
        try:
            data = json.loads(json_file.read_text())
            for r in data.get("results", []):
                findings.append({
                    "url": r.get("url", ""),
                    "status": r.get("status", 0),
                    "length": r.get("length", 0),
                    "words": r.get("words", 0),
                    "lines": r.get("lines", 0),
                    "target": target,
                    "source": "ffuf",
                })
        except Exception as e:
            self.logger.error(f"Error parsing ffuf JSON: {e}")
        return findings

    def _parse_feroxbuster(self, output_file: Path, target: str) -> List[Dict]:
        """Parse feroxbuster output."""
        findings = []
        try:
            for line in output_file.read_text().strip().split("\n"):
                if not line or line.startswith("#"):
                    continue
                # feroxbuster format: STATUS      LENGTH      LINES       WORDS       URL
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        findings.append({
                            "status": int(parts[0]),
                            "length": int(parts[1]),
                            "lines": int(parts[2]),
                            "words": int(parts[3]),
                            "url": parts[4],
                            "target": target,
                            "source": "feroxbuster",
                        })
                    except (ValueError, IndexError):
                        # Try alternative parsing (just URL)
                        if parts[-1].startswith("http"):
                            findings.append({
                                "url": parts[-1],
                                "status": 200,
                                "length": 0,
                                "target": target,
                                "source": "feroxbuster",
                            })
        except Exception as e:
            self.logger.error(f"Error parsing feroxbuster output: {e}")
        return findings

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Deduplicate findings by URL."""
        seen = set()
        unique = []
        for f in findings:
            url = f.get("url", "")
            if url and url not in seen:
                seen.add(url)
                unique.append(f)
        return unique

    def _categorize_and_write(
        self,
        findings: List[Dict],
        all_findings_file: Path,
        status_dir: Path,
        type_dir: Path,
        result: ModuleResult,
    ) -> None:
        """Categorize and write findings."""
        # Data structures
        by_status: Dict[int, List[Dict]] = defaultdict(list)
        by_type: Dict[str, List[Dict]] = defaultdict(list)

        for finding in findings:
            url = finding.get("url", "")
            status = finding.get("status", 0)
            url_lower = url.lower()

            # Group by status
            by_status[status].append(finding)

            # Categorize by type
            categorized = False
            for category, patterns in self.PATH_CATEGORIES.items():
                if any(p in url_lower for p in patterns):
                    by_type[category].append(finding)
                    categorized = True
                    break

            if not categorized:
                by_type["other"].append(finding)

            # Add to findings for high-priority items
            if any(p in url_lower for p in self.PATH_CATEGORIES["sensitive"]):
                result.findings.append({
                    "type": "sensitive_path",
                    "url": url,
                    "status": status,
                    "severity": "high",
                })
            elif any(p in url_lower for p in self.PATH_CATEGORIES["backup"]):
                result.findings.append({
                    "type": "backup_file",
                    "url": url,
                    "status": status,
                    "severity": "medium",
                })
            elif status in [401, 403]:
                result.findings.append({
                    "type": "access_restricted",
                    "url": url,
                    "status": status,
                    "severity": "low",
                })

        # Write all findings
        all_lines = [f"[{f['status']}] {f['url']}" for f in findings]
        self.write_output_file(all_findings_file, all_lines)
        result.output_files["all_findings"] = all_findings_file
        result.stats["total_findings"] = len(findings)

        self.logger.info(f"Total unique paths found: {len(findings)}")

        # Write by-status files
        for status, status_findings in by_status.items():
            status_file = status_dir / f"{status}.txt"
            urls = [f["url"] for f in status_findings]
            self.write_output_file(status_file, urls)
            result.output_files[f"status_{status}"] = status_file
            result.stats[f"status_{status}_count"] = len(status_findings)

        # Write by-type files
        for category, cat_findings in by_type.items():
            if cat_findings:
                type_file = type_dir / f"{category}.txt"
                lines = [f"[{f['status']}] {f['url']}" for f in cat_findings]
                self.write_output_file(type_file, lines)
                result.output_files[f"type_{category}"] = type_file
                result.stats[f"type_{category}_count"] = len(cat_findings)
                self.logger.info(f"  {category}: {len(cat_findings)} paths")

        # Log high-priority findings
        sensitive_count = len(by_type.get("sensitive", []))
        backup_count = len(by_type.get("backup", []))
        if sensitive_count > 0 or backup_count > 0:
            self.logger.warning(
                f"Found {sensitive_count} sensitive paths, {backup_count} backup files!"
            )

    def _save_json_summary(self, result: ModuleResult) -> None:
        """Save JSON summary."""
        summary = {
            "module": self.name,
            "stats": result.stats,
            "output_files": {k: str(v) for k, v in result.output_files.items()},
            "tools_used": list(self.available_tools),
            "findings_count": len(result.findings),
            "high_severity": len([f for f in result.findings if f.get("severity") == "high"]),
        }

        json_file = self.output_path / "fuzzing_summary.json"
        with open(json_file, "w") as f:
            json.dump(summary, f, indent=2)

        result.output_files["json_summary"] = json_file
