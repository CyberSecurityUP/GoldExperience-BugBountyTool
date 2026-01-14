"""
URL Collection Module - Enhanced Version

Collects historical URLs from archives and passive sources with command chaining:
- gau (GetAllUrls)
- waybackurls
- waymore

Output structure:
  urls/
    ├── raw/
    │   ├── gau.txt
    │   ├── waybackurls.txt
    │   └── waymore.txt
    ├── all_urls.txt (merged, deduplicated)
    ├── with_params.txt (URLs with query parameters)
    ├── js_files.txt
    ├── api_endpoints.txt
    ├── interesting_paths.txt
    ├── unique_params.txt
    └── url_collection_summary.json
"""

import json
import time
from pathlib import Path
from typing import List, Optional, Dict
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import PassiveModule, ModuleResult
from ..utils.process import ToolResult, check_tool_exists
from ..utils.dedup import merge_files, deduplicate_lines
from ..utils.normalize import normalize_url, normalize_domain, extract_params


class UrlCollectionModule(PassiveModule):
    """Enhanced passive URL collection with categorized output."""

    name = "url_collection"
    description = "Collect URLs from Wayback Machine, CommonCrawl, and other archives"
    tools = ["gau", "waybackurls", "waymore"]
    output_dir = "urls"

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        parallel: bool = True,
        **kwargs,
    ) -> ModuleResult:
        """
        Collect URLs for targets from passive sources.

        Args:
            targets: List of domains to collect URLs for
            resume: Skip if output exists
            parallel: Run tools in parallel

        Returns:
            ModuleResult with categorized collected URLs
        """
        start_time = time.time()
        self.ensure_output_dir()

        result = ModuleResult(
            module_name=self.name,
            success=True,
            duration=0.0,
        )

        # Create raw directory
        raw_dir = self.output_path / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        # Normalize domains
        targets = [normalize_domain(t) for t in targets if normalize_domain(t)]
        targets = list(set(targets))

        if not targets:
            self.logger.warning("No valid targets for URL collection")
            result.success = False
            result.duration = time.time() - start_time
            return result

        self.logger.info(f"{'='*50}")
        self.logger.info(f"Collecting URLs for {len(targets)} domains")
        self.logger.info(f"{'='*50}")

        # Output files
        all_urls_file = self.output_path / "all_urls.txt"

        if resume and all_urls_file.exists() and all_urls_file.stat().st_size > 0:
            self.logger.info("Resuming: Using existing URL collection results")
            urls = self.read_input_file(all_urls_file)
            result.stats["total_urls"] = len(urls)
            self._categorize_urls(urls, result)
            result.duration = time.time() - start_time
            return result

        # Collect URLs per target and tool
        tool_outputs = {}

        for domain in targets:
            self.logger.info(f"Collecting URLs for: {domain}")

            if parallel and len(self.available_tools) > 1:
                domain_outputs = self._run_parallel(domain, raw_dir, result)
            else:
                domain_outputs = self._run_sequential(domain, raw_dir, result)

            # Merge domain tool outputs
            for tool_name, output_file in domain_outputs.items():
                if tool_name not in tool_outputs:
                    tool_outputs[tool_name] = []
                tool_outputs[tool_name].append(output_file)

        # Merge all tool outputs
        all_urls = []
        for tool_name, files in tool_outputs.items():
            tool_merged = raw_dir / f"{tool_name}_all.txt"
            tool_urls = []
            for f in files:
                if f.exists():
                    tool_urls.extend(self.read_input_file(f))

            if tool_urls:
                tool_urls = deduplicate_lines(tool_urls, normalize_fn=normalize_url)
                self.write_output_file(tool_merged, tool_urls)
                all_urls.extend(tool_urls)
                result.stats[f"{tool_name}_count"] = len(tool_urls)
                self.logger.info(f"  {tool_name}: {len(tool_urls)} URLs")

        # Final deduplication and scope filtering
        all_urls = deduplicate_lines(all_urls, normalize_fn=normalize_url)
        all_urls = self.filter_scope(all_urls)

        # Write consolidated output
        self.write_output_file(all_urls_file, all_urls)
        result.output_files["all_urls"] = all_urls_file
        result.stats["total_urls"] = len(all_urls)

        self.logger.info(f"Total unique URLs: {len(all_urls)}")

        # Categorize URLs
        self._categorize_urls(all_urls, result)

        # Save JSON summary
        self._save_json_summary(result)

        result.duration = time.time() - start_time
        return result

    def _run_parallel(
        self,
        domain: str,
        raw_dir: Path,
        result: ModuleResult,
    ) -> Dict[str, Path]:
        """Run URL collectors in parallel for a domain."""
        tool_outputs = {}

        with ThreadPoolExecutor(max_workers=len(self.available_tools)) as executor:
            futures = {}

            collectors = [
                ("gau", self._run_gau),
                ("waybackurls", self._run_waybackurls),
                ("waymore", self._run_waymore),
            ]

            for tool_name, collector_func in collectors:
                if check_tool_exists(tool_name):
                    output_file = raw_dir / f"{domain}_{tool_name}.txt"
                    future = executor.submit(collector_func, domain, output_file)
                    futures[future] = (tool_name, output_file)

            for future in as_completed(futures):
                tool_name, output_file = futures[future]
                try:
                    tool_result = future.result()
                    result.add_tool_result(tool_result)
                    if tool_result.success:
                        tool_outputs[tool_name] = output_file
                except Exception as e:
                    self.logger.error(f"Error running {tool_name}: {e}")

        return tool_outputs

    def _run_sequential(
        self,
        domain: str,
        raw_dir: Path,
        result: ModuleResult,
    ) -> Dict[str, Path]:
        """Run URL collectors sequentially for a domain."""
        tool_outputs = {}

        collectors = [
            ("gau", self._run_gau),
            ("waybackurls", self._run_waybackurls),
            ("waymore", self._run_waymore),
        ]

        for tool_name, collector_func in collectors:
            if check_tool_exists(tool_name):
                output_file = raw_dir / f"{domain}_{tool_name}.txt"
                tool_result = collector_func(domain, output_file)
                result.add_tool_result(tool_result)
                if tool_result.success:
                    tool_outputs[tool_name] = output_file

        return tool_outputs

    def _run_gau(self, domain: str, output_file: Path) -> ToolResult:
        """Run gau (GetAllUrls)."""
        args = [
            "--threads", "5",
            "--timeout", "60",
            "--subs",  # Include subdomains
            "--providers", "wayback,commoncrawl,otx,urlscan",
            "--o", str(output_file),
            domain,
        ]
        return self.run_tool("gau", args, timeout=600)

    def _run_waybackurls(self, domain: str, output_file: Path) -> ToolResult:
        """Run waybackurls."""
        # Don't use -dates flag as it causes parsing issues
        args = [domain]
        return self.run_tool(
            "waybackurls",
            args,
            output_file=output_file,
            timeout=300,
        )

    def _run_waymore(self, domain: str, output_file: Path) -> ToolResult:
        """Run waymore for comprehensive URL collection."""
        waymore_dir = output_file.parent / f"waymore_{domain}"
        waymore_dir.mkdir(exist_ok=True)

        args = [
            "-i", domain,
            "-mode", "U",  # URL mode
            "-oU", str(output_file),
            "-p", "5",  # Processes
            "-xwm",  # Exclude wayback machine URLs already collected
        ]

        result = self.run_tool("waymore", args, timeout=900)

        # waymore may create additional files, merge them
        if result.success and waymore_dir.exists():
            extra_urls = []
            for f in waymore_dir.glob("*.txt"):
                extra_urls.extend(f.read_text().strip().split("\n"))
            if extra_urls and output_file.exists():
                existing = output_file.read_text().strip().split("\n")
                all_urls = list(set(existing + extra_urls))
                output_file.write_text("\n".join(all_urls))
                result.result_count = len(all_urls)

        return result

    def _categorize_urls(self, urls: List[str], result: ModuleResult) -> None:
        """Categorize URLs into different types."""
        params_urls = []
        js_files = []
        api_endpoints = []
        interesting_paths = []
        static_files = []
        extensions = {}
        all_params = set()

        for url in urls:
            url_lower = url.lower()
            parsed = urlparse(url)
            path = parsed.path.lower()

            # Count extensions
            if "." in path.split("/")[-1]:
                ext = path.split("/")[-1].split(".")[-1].split("?")[0]
                if len(ext) <= 5 and ext.isalnum():
                    extensions[ext] = extensions.get(ext, 0) + 1

            # URLs with parameters
            if "?" in url and "=" in url:
                params_urls.append(url)
                # Extract params
                params = extract_params(url)
                all_params.update(params.keys())

            # JavaScript files
            if path.endswith(".js") or ".js?" in url_lower or "/js/" in path:
                js_files.append(url)

            # API endpoints
            api_indicators = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/json/", "/xml/"]
            if any(p in url_lower for p in api_indicators):
                api_endpoints.append(url)

            # Interesting paths
            interesting_indicators = [
                "admin", "dashboard", "config", "backup", "debug", "test",
                "dev", "staging", "internal", ".git", ".env", ".svn",
                "phpinfo", "phpmyadmin", "wp-admin", "manager", "console",
                "actuator", "swagger", "api-docs", "graphiql", "metrics",
                "health", "status", "info", "dump", "export", "download",
            ]
            if any(p in url_lower for p in interesting_indicators):
                interesting_paths.append(url)

            # Static files for filtering
            static_exts = [".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf"]
            if any(path.endswith(ext) for ext in static_exts):
                static_files.append(url)

        # Write categorized files
        categories = {
            "with_params": params_urls,
            "js_files": js_files,
            "api_endpoints": api_endpoints,
            "interesting_paths": interesting_paths,
        }

        for cat_name, cat_urls in categories.items():
            if cat_urls:
                cat_file = self.output_path / f"{cat_name}.txt"
                cat_urls_unique = list(set(cat_urls))
                self.write_output_file(cat_file, cat_urls_unique)
                result.output_files[cat_name] = cat_file
                result.stats[f"{cat_name}_count"] = len(cat_urls_unique)
                self.logger.info(f"  {cat_name}: {len(cat_urls_unique)}")

        # Write unique parameter names
        if all_params:
            params_file = self.output_path / "unique_params.txt"
            self.write_output_file(params_file, sorted(all_params))
            result.output_files["unique_params"] = params_file
            result.stats["unique_params_count"] = len(all_params)

            # Flag interesting parameters
            interesting_param_patterns = [
                "id", "user", "admin", "token", "key", "secret", "password",
                "pass", "file", "path", "url", "redirect", "callback", "return",
                "next", "debug", "test", "cmd", "exec", "query", "sql",
            ]
            interesting_found = [p for p in all_params if any(
                pattern in p.lower() for pattern in interesting_param_patterns
            )]
            if interesting_found:
                result.findings.extend([
                    {"type": "interesting_parameter", "param": p, "source": "url_collection"}
                    for p in interesting_found[:20]
                ])

        # Store extension statistics
        result.metadata["extensions"] = dict(sorted(
            extensions.items(),
            key=lambda x: x[1],
            reverse=True
        )[:30])

    def _save_json_summary(self, result: ModuleResult) -> None:
        """Save JSON summary."""
        summary = {
            "module": self.name,
            "stats": result.stats,
            "output_files": {k: str(v) for k, v in result.output_files.items()},
            "tools_used": list(self.available_tools),
            "extensions": result.metadata.get("extensions", {}),
            "findings_count": len(result.findings),
        }

        json_file = self.output_path / "url_collection_summary.json"
        with open(json_file, "w") as f:
            json.dump(summary, f, indent=2)

        result.output_files["json_summary"] = json_file
