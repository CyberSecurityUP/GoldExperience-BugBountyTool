"""
Subdomain Enumeration Module - Enhanced Version

Uses multiple tools with command chaining for maximum coverage:
- subfinder
- amass
- assetfinder
- findomain
- chaos
- crt.sh (passive)
- DNS bruteforce with shuffledns/puredns

Output structure:
  subdomains/
    ├── raw/
    │   ├── subfinder.txt
    │   ├── amass.txt
    │   ├── assetfinder.txt
    │   ├── findomain.txt
    │   ├── chaos.txt
    │   └── crtsh.txt
    ├── all_subdomains.txt (merged, deduplicated)
    ├── resolved.txt (only DNS resolved)
    └── alive.txt (HTTP alive - ready for next phase)
"""

import json
import time
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen
from urllib.error import URLError

from .base import BaseModule, ModuleResult, PassiveModule
from ..utils.process import ToolResult, run_tool, check_tool_exists
from ..utils.dedup import deduplicate_lines, merge_files
from ..utils.normalize import normalize_domain


class SubdomainEnumModule(PassiveModule):
    """Enhanced subdomain enumeration with command chaining."""

    name = "subdomain_enum"
    description = "Discover subdomains using multiple passive and active techniques"
    tools = ["subfinder", "amass", "assetfinder", "findomain", "chaos", "dnsx", "shuffledns"]
    output_dir = "subdomains"

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        parallel: bool = True,
        **kwargs,
    ) -> ModuleResult:
        """
        Run comprehensive subdomain enumeration.

        Args:
            targets: List of domains to enumerate
            resume: Skip if output exists
            parallel: Run tools in parallel

        Returns:
            ModuleResult with discovered subdomains
        """
        start_time = time.time()
        self.ensure_output_dir()

        result = ModuleResult(
            module_name=self.name,
            success=True,
            duration=0.0,
        )

        # Create output directories
        raw_dir = self.output_path / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        all_subdomains = []

        for target in targets:
            target = normalize_domain(target)
            if not target:
                continue

            self.logger.info(f"{'='*50}")
            self.logger.info(f"Enumerating subdomains for: {target}")
            self.logger.info(f"{'='*50}")

            # Output files
            merged_file = self.output_path / f"{target}_all.txt"
            resolved_file = self.output_path / f"{target}_resolved.txt"
            alive_file = self.output_path / f"{target}_alive.txt"

            # Check resume
            if resume and merged_file.exists() and merged_file.stat().st_size > 0:
                self.logger.info(f"Resuming: Using existing results for {target}")
                subdomains = self.read_input_file(merged_file)
                all_subdomains.extend(subdomains)
                result.stats[f"{target}_count"] = len(subdomains)
                continue

            # ===== Phase 1: Passive Enumeration =====
            self.logger.info("[Phase 1] Passive Enumeration")

            tool_outputs = {}

            if parallel:
                tool_outputs = self._run_passive_parallel(target, raw_dir, result)
            else:
                tool_outputs = self._run_passive_sequential(target, raw_dir, result)

            # Also get from crt.sh (certificate transparency)
            crtsh_file = raw_dir / f"{target}_crtsh.txt"
            crtsh_subs = self._get_crtsh(target)
            if crtsh_subs:
                self.write_output_file(crtsh_file, crtsh_subs)
                tool_outputs["crtsh"] = crtsh_file
                result.stats["crtsh_count"] = len(crtsh_subs)

            # Merge all results
            all_files = list(tool_outputs.values())
            if all_files:
                # Merge and deduplicate
                merged_subs = []
                for f in all_files:
                    if f.exists():
                        merged_subs.extend(self.read_input_file(f))

                merged_subs = self.deduplicate(merged_subs, normalize_domain)
                merged_subs = self.filter_scope(merged_subs)
                self.write_output_file(merged_file, merged_subs)

                result.output_files[f"{target}_all"] = merged_file
                result.stats[f"{target}_passive_count"] = len(merged_subs)
                self.logger.info(f"[Phase 1] Found {len(merged_subs)} unique subdomains")

                # ===== Phase 2: DNS Resolution =====
                self.logger.info("[Phase 2] DNS Resolution")
                resolved_subs = self._resolve_subdomains(merged_file, resolved_file)
                if resolved_subs:
                    result.output_files[f"{target}_resolved"] = resolved_file
                    result.stats[f"{target}_resolved_count"] = len(resolved_subs)
                    self.logger.info(f"[Phase 2] {len(resolved_subs)} subdomains resolved")

                # ===== Phase 3: HTTP Probing (for chaining) =====
                self.logger.info("[Phase 3] HTTP Probing")
                alive_subs = self._probe_http(resolved_file, alive_file)
                if alive_subs:
                    result.output_files[f"{target}_alive"] = alive_file
                    result.stats[f"{target}_alive_count"] = len(alive_subs)
                    self.logger.info(f"[Phase 3] {len(alive_subs)} alive HTTP services")

                all_subdomains.extend(merged_subs)

        # Create final consolidated files
        if all_subdomains:
            all_subdomains = self.deduplicate(all_subdomains, normalize_domain)

            # All subdomains
            final_all = self.output_path / "all_subdomains.txt"
            self.write_output_file(final_all, all_subdomains)
            result.output_files["all_subdomains"] = final_all

            # All resolved
            final_resolved = self.output_path / "all_resolved.txt"
            self._merge_resolved_files(final_resolved)
            result.output_files["all_resolved"] = final_resolved

            # All alive
            final_alive = self.output_path / "all_alive.txt"
            self._merge_alive_files(final_alive)
            result.output_files["all_alive"] = final_alive

            result.stats["total_subdomains"] = len(all_subdomains)

        # Save JSON summary
        self._save_json_summary(result)

        result.duration = time.time() - start_time
        return result

    def _run_passive_parallel(
        self,
        target: str,
        raw_dir: Path,
        result: ModuleResult,
    ) -> Dict[str, Path]:
        """Run passive enumeration tools in parallel."""
        tool_outputs = {}

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}

            tools_to_run = [
                ("subfinder", self._run_subfinder),
                ("amass", self._run_amass),
                ("assetfinder", self._run_assetfinder),
                ("findomain", self._run_findomain),
                ("chaos", self._run_chaos),
            ]

            for tool_name, tool_func in tools_to_run:
                if check_tool_exists(tool_name):
                    output_file = raw_dir / f"{target}_{tool_name}.txt"
                    future = executor.submit(tool_func, target, output_file)
                    futures[future] = (tool_name, output_file)

            for future in as_completed(futures):
                tool_name, output_file = futures[future]
                try:
                    tool_result = future.result()
                    result.add_tool_result(tool_result)
                    if tool_result.success and output_file.exists():
                        tool_outputs[tool_name] = output_file
                        count = len(self.read_input_file(output_file))
                        result.stats[f"{tool_name}_count"] = count
                        self.logger.info(f"  {tool_name}: {count} subdomains")
                except Exception as e:
                    self.logger.error(f"Error running {tool_name}: {e}")

        return tool_outputs

    def _run_passive_sequential(
        self,
        target: str,
        raw_dir: Path,
        result: ModuleResult,
    ) -> Dict[str, Path]:
        """Run passive enumeration tools sequentially."""
        tool_outputs = {}

        tools = [
            ("subfinder", self._run_subfinder),
            ("amass", self._run_amass),
            ("assetfinder", self._run_assetfinder),
            ("findomain", self._run_findomain),
            ("chaos", self._run_chaos),
        ]

        for tool_name, tool_func in tools:
            if check_tool_exists(tool_name):
                output_file = raw_dir / f"{target}_{tool_name}.txt"
                tool_result = tool_func(target, output_file)
                result.add_tool_result(tool_result)
                if tool_result.success and output_file.exists():
                    tool_outputs[tool_name] = output_file
                    count = len(self.read_input_file(output_file))
                    result.stats[f"{tool_name}_count"] = count
                    self.logger.info(f"  {tool_name}: {count} subdomains")

        return tool_outputs

    def _run_subfinder(self, target: str, output_file: Path) -> ToolResult:
        """Run subfinder."""
        args = ["-d", target, "-o", str(output_file), "-all", "-silent"]
        return self.run_tool("subfinder", args, timeout=300)

    def _run_amass(self, target: str, output_file: Path) -> ToolResult:
        """Run amass passive enumeration."""
        args = ["enum", "-passive", "-d", target, "-o", str(output_file)]
        return self.run_tool("amass", args, timeout=600)

    def _run_assetfinder(self, target: str, output_file: Path) -> ToolResult:
        """Run assetfinder."""
        args = ["--subs-only", target]
        return self.run_tool("assetfinder", args, output_file=output_file, timeout=180)

    def _run_findomain(self, target: str, output_file: Path) -> ToolResult:
        """Run findomain."""
        args = ["-t", target, "-u", str(output_file), "-q"]
        return self.run_tool("findomain", args, timeout=300)

    def _run_chaos(self, target: str, output_file: Path) -> ToolResult:
        """Run chaos client."""
        args = ["-d", target, "-o", str(output_file), "-silent"]
        return self.run_tool("chaos", args, timeout=180)

    def _get_crtsh(self, target: str) -> List[str]:
        """Get subdomains from crt.sh (Certificate Transparency)."""
        self.logger.info("  Querying crt.sh...")
        try:
            url = f"https://crt.sh/?q=%.{target}&output=json"
            with urlopen(url, timeout=30) as response:
                data = json.loads(response.read().decode())

            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub and "*" not in sub:
                        subdomains.add(sub)

            self.logger.info(f"  crt.sh: {len(subdomains)} subdomains")
            return list(subdomains)
        except Exception as e:
            self.logger.warning(f"  crt.sh failed: {e}")
            return []

    def _resolve_subdomains(self, input_file: Path, output_file: Path) -> List[str]:
        """Resolve subdomains using dnsx."""
        if not check_tool_exists("dnsx"):
            self.logger.warning("dnsx not found, skipping resolution")
            return []

        args = [
            "-l", str(input_file),
            "-o", str(output_file),
            "-silent",
            "-threads", "100",
            "-retry", "2",
        ]

        result = self.run_tool("dnsx", args, timeout=300)
        if result.success and output_file.exists():
            return self.read_input_file(output_file)
        return []

    def _probe_http(self, input_file: Path, output_file: Path) -> List[str]:
        """Probe for HTTP services using httpx."""
        if not input_file.exists():
            return []

        if not check_tool_exists("httpx"):
            self.logger.warning("httpx not found, skipping HTTP probe")
            return []

        args = [
            "-l", str(input_file),
            "-o", str(output_file),
            "-silent",
            "-threads", "50",
            "-timeout", "10",
        ]

        result = self.run_tool("httpx", args, timeout=300)
        if result.success and output_file.exists():
            return self.read_input_file(output_file)
        return []

    def _merge_resolved_files(self, output_file: Path) -> None:
        """Merge all resolved files."""
        resolved_files = list(self.output_path.glob("*_resolved.txt"))
        if resolved_files:
            merge_files(resolved_files, output_file, deduplicate=True)

    def _merge_alive_files(self, output_file: Path) -> None:
        """Merge all alive files."""
        alive_files = list(self.output_path.glob("*_alive.txt"))
        if alive_files:
            merge_files(alive_files, output_file, deduplicate=True)

    def _save_json_summary(self, result: ModuleResult) -> None:
        """Save JSON summary of subdomain enumeration."""
        summary = {
            "module": self.name,
            "stats": result.stats,
            "output_files": {k: str(v) for k, v in result.output_files.items()},
            "tools_used": list(self.available_tools),
        }

        json_file = self.output_path / "subdomain_summary.json"
        with open(json_file, "w") as f:
            json.dump(summary, f, indent=2)

        result.output_files["json_summary"] = json_file
