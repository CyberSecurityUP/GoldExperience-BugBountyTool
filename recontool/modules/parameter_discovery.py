"""
Parameter Discovery Module - Enhanced Version

Discovers hidden parameters in web applications:
- arjun
- x8
- paramspider

Output structure:
  params/
    ├── raw/
    │   ├── arjun.txt
    │   ├── x8.txt
    │   └── paramspider.txt
    ├── all_params.txt (merged URLs with params)
    ├── param_names.txt (unique parameter names)
    ├── interesting_params.txt
    ├── by_type/
    │   ├── id_params.txt
    │   ├── auth_params.txt
    │   ├── file_params.txt
    │   └── redirect_params.txt
    └── parameter_discovery_summary.json
"""

import json
import time
from pathlib import Path
from typing import List, Optional, Dict, Set
from urllib.parse import parse_qs, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import ActiveModule, ModuleResult
from ..utils.process import ToolResult, check_tool_exists
from ..utils.dedup import merge_files, deduplicate_lines


class ParameterDiscoveryModule(ActiveModule):
    """Enhanced parameter discovery with categorized output."""

    name = "parameter_discovery"
    description = "Discover hidden parameters in web application endpoints"
    tools = ["arjun", "x8", "paramspider"]
    output_dir = "params"

    # Interesting parameter patterns for categorization
    PARAM_CATEGORIES = {
        "id_params": ["id", "uid", "user_id", "userid", "account", "pid", "item", "product"],
        "auth_params": ["token", "key", "api_key", "apikey", "auth", "session", "jwt", "access_token", "password", "pass", "pwd", "secret"],
        "file_params": ["file", "filename", "path", "filepath", "doc", "document", "upload", "download", "read", "write", "src", "source"],
        "redirect_params": ["url", "redirect", "return", "returnurl", "return_url", "next", "goto", "callback", "continue", "dest", "destination", "redir"],
        "injection_params": ["query", "q", "search", "filter", "sort", "order", "cmd", "exec", "command", "sql", "data", "input"],
        "debug_params": ["debug", "test", "dev", "verbose", "log", "trace", "mode", "admin"],
    }

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        wordlist: Optional[Path] = None,
        **kwargs,
    ) -> ModuleResult:
        """
        Discover parameters for target URLs.

        Args:
            targets: List of URLs to test
            resume: Skip if output exists
            input_file: File containing URLs
            wordlist: Custom parameter wordlist

        Returns:
            ModuleResult with discovered parameters
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
        by_type_dir = self.output_path / "by_type"
        by_type_dir.mkdir(parents=True, exist_ok=True)

        # Load targets
        if input_file and input_file.exists():
            targets = self.read_input_file(input_file)

        if not targets:
            self.logger.warning("No targets provided for parameter discovery")
            result.duration = time.time() - start_time
            return result

        # Filter and deduplicate
        targets = self.filter_scope(targets)
        targets = list(set(targets))

        # Limit targets for active testing
        if len(targets) > 100:
            self.logger.warning(f"Limiting to 100 targets (had {len(targets)})")
            targets = targets[:100]

        self.logger.info(f"{'='*50}")
        self.logger.info(f"Discovering parameters for {len(targets)} URLs")
        self.logger.info(f"{'='*50}")

        # Write targets
        targets_file = self.output_path / "targets.txt"
        self.write_output_file(targets_file, targets)

        # Output files
        all_params_file = self.output_path / "all_params.txt"

        if resume and all_params_file.exists() and all_params_file.stat().st_size > 0:
            self.logger.info("Resuming: Using existing parameter discovery results")
            result.duration = time.time() - start_time
            return result

        tool_outputs = {}

        # Run paramspider (passive, faster)
        if check_tool_exists("paramspider"):
            ps_output = raw_dir / "paramspider.txt"
            ps_result = self._run_paramspider(targets, ps_output)
            result.add_tool_result(ps_result)
            if ps_result.success and ps_output.exists():
                tool_outputs["paramspider"] = ps_output
                count = len(self.read_input_file(ps_output))
                result.stats["paramspider_count"] = count
                self.logger.info(f"  paramspider: {count} URLs with params")

        # Run arjun (active probing)
        if check_tool_exists("arjun"):
            arjun_output = raw_dir / "arjun.txt"
            arjun_result = self._run_arjun(targets_file, arjun_output, wordlist)
            result.add_tool_result(arjun_result)
            if arjun_result.success and arjun_output.exists():
                tool_outputs["arjun"] = arjun_output
                count = len(self.read_input_file(arjun_output))
                result.stats["arjun_count"] = count
                self.logger.info(f"  arjun: {count} discovered params")

        # Run x8 (active probing)
        if check_tool_exists("x8"):
            x8_output = raw_dir / "x8.txt"
            x8_result = self._run_x8(targets_file, x8_output, wordlist)
            result.add_tool_result(x8_result)
            if x8_result.success and x8_output.exists():
                tool_outputs["x8"] = x8_output
                count = len(self.read_input_file(x8_output))
                result.stats["x8_count"] = count
                self.logger.info(f"  x8: {count} discovered params")

        # Merge results
        if tool_outputs:
            all_urls = []
            for tool_name, output_file in tool_outputs.items():
                if output_file.exists():
                    all_urls.extend(self.read_input_file(output_file))

            all_urls = deduplicate_lines(all_urls)
            self.write_output_file(all_params_file, all_urls)
            result.output_files["all_params"] = all_params_file
            result.stats["total_urls_with_params"] = len(all_urls)

            # Extract and categorize parameters
            self._extract_and_categorize_params(all_urls, by_type_dir, result)

            self.logger.info(f"Total URLs with parameters: {len(all_urls)}")

        # Save JSON summary
        self._save_json_summary(result)

        result.duration = time.time() - start_time
        return result

    def _run_paramspider(self, targets: List[str], output_file: Path) -> ToolResult:
        """Run paramspider for passive parameter discovery."""
        all_results = []

        for target in targets[:50]:  # Limit
            # Extract domain from URL
            parsed = urlparse(target)
            domain = parsed.netloc or parsed.path.split("/")[0]

            if not domain:
                continue

            temp_output = output_file.parent / f"ps_{domain.replace('.', '_')}.txt"
            args = [
                "-d", domain,
                "--level", "high",
                "-o", str(temp_output),
            ]

            result = self.run_tool("paramspider", args, timeout=120)
            if result.success and temp_output.exists():
                all_results.extend(self.read_input_file(temp_output))

        if all_results:
            output_file.write_text("\n".join(list(set(all_results))))
            result.result_count = len(set(all_results))

        return result

    def _run_arjun(
        self,
        input_file: Path,
        output_file: Path,
        wordlist: Optional[Path],
    ) -> ToolResult:
        """Run arjun for active parameter discovery."""
        args = [
            "-i", str(input_file),
            "-oT", str(output_file),
            "-t", "10",
            "--stable",
            "-q",  # Quiet mode
        ]

        if wordlist and wordlist.exists():
            args.extend(["-w", str(wordlist)])

        return self.run_tool("arjun", args, timeout=900)

    def _run_x8(
        self,
        input_file: Path,
        output_file: Path,
        wordlist: Optional[Path],
    ) -> ToolResult:
        """Run x8 for active parameter discovery."""
        args = [
            "-u", str(input_file),
            "-o", str(output_file),
            "-t", "10",
        ]

        if wordlist and wordlist.exists():
            args.extend(["-w", str(wordlist)])

        return self.run_tool("x8", args, timeout=900)

    def _extract_and_categorize_params(
        self,
        urls: List[str],
        by_type_dir: Path,
        result: ModuleResult,
    ) -> None:
        """Extract and categorize parameter names."""
        all_params: Set[str] = set()
        param_urls: Dict[str, List[str]] = {cat: [] for cat in self.PARAM_CATEGORIES}
        interesting_params: List[Dict] = []

        for url in urls:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                for param_name in params.keys():
                    all_params.add(param_name)
                    param_lower = param_name.lower()

                    # Categorize
                    for category, patterns in self.PARAM_CATEGORIES.items():
                        if any(pattern in param_lower for pattern in patterns):
                            param_urls[category].append(url)

                            # Mark as interesting finding
                            if category in ["auth_params", "file_params", "redirect_params", "injection_params"]:
                                interesting_params.append({
                                    "url": url,
                                    "param": param_name,
                                    "category": category,
                                })
                            break

            except Exception:
                continue

        # Write unique param names
        if all_params:
            names_file = self.output_path / "param_names.txt"
            self.write_output_file(names_file, sorted(all_params))
            result.output_files["param_names"] = names_file
            result.stats["unique_params"] = len(all_params)
            self.logger.info(f"  Unique parameter names: {len(all_params)}")

        # Write categorized files
        for category, urls_list in param_urls.items():
            if urls_list:
                cat_file = by_type_dir / f"{category}.txt"
                unique_urls = list(set(urls_list))
                self.write_output_file(cat_file, unique_urls)
                result.output_files[category] = cat_file
                result.stats[f"{category}_count"] = len(unique_urls)
                self.logger.info(f"  {category}: {len(unique_urls)}")

        # Write interesting params
        if interesting_params:
            interesting_file = self.output_path / "interesting_params.txt"
            lines = [f"{p['category']}: {p['param']} -> {p['url']}" for p in interesting_params]
            self.write_output_file(interesting_file, list(set(lines)))
            result.output_files["interesting_params"] = interesting_file

            # Add to findings
            for item in interesting_params[:30]:
                severity = "high" if item["category"] in ["auth_params", "injection_params"] else "medium"
                result.findings.append({
                    "type": "interesting_parameter",
                    "category": item["category"],
                    "param": item["param"],
                    "url": item["url"],
                    "severity": severity,
                })

    def _save_json_summary(self, result: ModuleResult) -> None:
        """Save JSON summary."""
        summary = {
            "module": self.name,
            "stats": result.stats,
            "output_files": {k: str(v) for k, v in result.output_files.items()},
            "tools_used": list(self.available_tools),
            "findings_count": len(result.findings),
            "categories": {
                cat: result.stats.get(f"{cat}_count", 0)
                for cat in self.PARAM_CATEGORIES
            },
        }

        json_file = self.output_path / "parameter_discovery_summary.json"
        with open(json_file, "w") as f:
            json.dump(summary, f, indent=2)

        result.output_files["json_summary"] = json_file
