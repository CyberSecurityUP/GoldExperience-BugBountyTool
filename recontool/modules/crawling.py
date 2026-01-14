"""
Crawling and Spidering Module - Enhanced Version

Crawls live web services with command chaining:
- katana (main crawler)
- gospider
- hakrawler
- cariddi

Output structure:
  crawling/
    ├── raw/
    │   ├── katana.txt
    │   ├── gospider.txt
    │   ├── hakrawler.txt
    │   └── cariddi.txt
    ├── all_urls.txt (merged, deduplicated)
    ├── js_files.txt
    ├── api_endpoints.txt
    ├── params_urls.txt (URLs with parameters)
    ├── forms.txt
    └── crawling_summary.json
"""

import json
import time
from pathlib import Path
from typing import List, Optional, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

from .base import ActiveModule, ModuleResult
from ..utils.process import ToolResult, check_tool_exists
from ..utils.dedup import merge_files, deduplicate_lines
from ..utils.normalize import normalize_url, extract_params


class CrawlingModule(ActiveModule):
    """Enhanced web crawling with categorized output."""

    name = "crawling"
    description = "Crawl web applications to discover endpoints, JS files, and parameters"
    tools = ["katana", "gospider", "hakrawler", "cariddi"]
    output_dir = "crawling"

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        depth: int = 3,
        parallel: bool = True,
        **kwargs,
    ) -> ModuleResult:
        """
        Run comprehensive web crawling.

        Args:
            targets: List of URLs to crawl
            resume: Skip if output exists
            input_file: File containing URLs
            depth: Crawl depth
            parallel: Run tools in parallel

        Returns:
            ModuleResult with categorized URLs
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

        # Load targets
        if input_file and input_file.exists():
            targets = self.read_input_file(input_file)

        if not targets:
            self.logger.warning("No targets for crawling")
            result.success = False
            result.duration = time.time() - start_time
            return result

        # Filter and prepare
        targets = self.filter_scope(targets)
        targets = list(set(targets))

        self.logger.info(f"{'='*50}")
        self.logger.info(f"Crawling {len(targets)} targets")
        self.logger.info(f"{'='*50}")

        # Write targets
        targets_file = self.output_path / "targets.txt"
        self.write_output_file(targets_file, targets)

        # Output files
        all_urls_file = self.output_path / "all_urls.txt"

        if resume and all_urls_file.exists() and all_urls_file.stat().st_size > 0:
            self.logger.info("Resuming: Using existing crawl results")
            urls = self.read_input_file(all_urls_file)
            result.stats["total_urls"] = len(urls)
            self._categorize_urls(urls, result)
            result.duration = time.time() - start_time
            return result

        # Run crawlers
        tool_outputs = {}

        if parallel and len(self.available_tools) > 1:
            tool_outputs = self._run_parallel(targets_file, raw_dir, depth, result)
        else:
            tool_outputs = self._run_sequential(targets_file, raw_dir, depth, result)

        # Merge all results
        all_urls = []
        for tool_name, output_file in tool_outputs.items():
            if output_file.exists():
                urls = self.read_input_file(output_file)
                all_urls.extend(urls)
                result.stats[f"{tool_name}_count"] = len(urls)
                self.logger.info(f"  {tool_name}: {len(urls)} URLs")

        # Deduplicate and filter
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
        targets_file: Path,
        raw_dir: Path,
        depth: int,
        result: ModuleResult,
    ) -> Dict[str, Path]:
        """Run crawlers in parallel."""
        tool_outputs = {}

        with ThreadPoolExecutor(max_workers=len(self.available_tools)) as executor:
            futures = {}

            crawlers = [
                ("katana", self._run_katana),
                ("gospider", self._run_gospider),
                ("hakrawler", self._run_hakrawler),
                ("cariddi", self._run_cariddi),
            ]

            for tool_name, crawler_func in crawlers:
                if check_tool_exists(tool_name):
                    output_file = raw_dir / f"{tool_name}.txt"
                    future = executor.submit(
                        crawler_func, targets_file, output_file, depth
                    )
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
        targets_file: Path,
        raw_dir: Path,
        depth: int,
        result: ModuleResult,
    ) -> Dict[str, Path]:
        """Run crawlers sequentially."""
        tool_outputs = {}

        crawlers = [
            ("katana", self._run_katana),
            ("gospider", self._run_gospider),
            ("hakrawler", self._run_hakrawler),
            ("cariddi", self._run_cariddi),
        ]

        for tool_name, crawler_func in crawlers:
            if check_tool_exists(tool_name):
                output_file = raw_dir / f"{tool_name}.txt"
                tool_result = crawler_func(targets_file, output_file, depth)
                result.add_tool_result(tool_result)
                if tool_result.success:
                    tool_outputs[tool_name] = output_file

        return tool_outputs

    def _run_katana(self, input_file: Path, output_file: Path, depth: int) -> ToolResult:
        """Run katana web crawler."""
        args = [
            "-list", str(input_file),
            "-o", str(output_file),
            "-d", str(depth),
            "-jc",  # JavaScript crawling
            "-kf", "all",
            "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",
            "-silent",
            "-c", "20",
            "-timeout", "10",
            "-aff",  # Automatic form fill
        ]
        return self.run_tool("katana", args, timeout=900)

    def _run_gospider(self, input_file: Path, output_file: Path, depth: int) -> ToolResult:
        """Run gospider web crawler."""
        gospider_dir = output_file.parent / "gospider_out"
        gospider_dir.mkdir(exist_ok=True)

        args = [
            "-S", str(input_file),
            "-o", str(gospider_dir),
            "-d", str(depth),
            "-c", "10",
            "-t", "5",
            "--js",
            "-a",
            "--sitemap",
            "--robots",
            "-q",
        ]

        result = self.run_tool("gospider", args, timeout=900)

        # Merge gospider output files
        if result.success and gospider_dir.exists():
            all_urls = []
            for f in gospider_dir.glob("*"):
                if f.is_file():
                    for line in f.read_text().strip().split("\n"):
                        # Extract URL from gospider format
                        if " - " in line:
                            url = line.split(" - ")[-1].strip()
                            if url.startswith("http"):
                                all_urls.append(url)
                        elif line.startswith("http"):
                            all_urls.append(line)

            output_file.write_text("\n".join(all_urls))
            result.result_count = len(all_urls)

        return result

    def _run_hakrawler(self, input_file: Path, output_file: Path, depth: int) -> ToolResult:
        """Run hakrawler."""
        input_data = input_file.read_text()
        args = [
            "-d", str(depth),
            "-t", "10",
            "-timeout", "10",
            "-subs",
            "-u",
        ]
        return self.run_tool(
            "hakrawler",
            args,
            input_data=input_data,
            output_file=output_file,
            timeout=600,
        )

    def _run_cariddi(self, input_file: Path, output_file: Path, depth: int) -> ToolResult:
        """Run cariddi."""
        input_data = input_file.read_text()
        args = [
            "-s",
            "-e",
            "-ext", "3",
            "-c", "20",
            "-t", "10",
        ]
        return self.run_tool(
            "cariddi",
            args,
            input_data=input_data,
            output_file=output_file,
            timeout=600,
        )

    def _categorize_urls(self, urls: List[str], result: ModuleResult) -> None:
        """Categorize URLs into different types."""
        js_files = []
        api_endpoints = []
        params_urls = []
        forms = []
        static_files = []
        interesting = []

        for url in urls:
            url_lower = url.lower()
            parsed = urlparse(url)
            path = parsed.path.lower()

            # JavaScript files
            if path.endswith(".js") or "/js/" in path:
                js_files.append(url)

            # API endpoints
            if any(p in url_lower for p in ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"]):
                api_endpoints.append(url)

            # URLs with parameters
            if "?" in url and "=" in url:
                params_urls.append(url)

            # Forms (potential)
            if any(p in url_lower for p in ["login", "register", "signup", "contact", "search", "upload"]):
                forms.append(url)

            # Interesting paths
            if any(p in url_lower for p in [
                "admin", "dashboard", "config", "backup", "debug",
                "test", "dev", "staging", "internal", ".git", ".env"
            ]):
                interesting.append(url)

            # Static files (for filtering)
            if any(path.endswith(ext) for ext in [".css", ".png", ".jpg", ".gif", ".svg", ".ico"]):
                static_files.append(url)

        # Write categorized files
        categories = {
            "js_files": js_files,
            "api_endpoints": api_endpoints,
            "params_urls": params_urls,
            "forms": forms,
            "interesting": interesting,
        }

        for cat_name, cat_urls in categories.items():
            if cat_urls:
                cat_file = self.output_path / f"{cat_name}.txt"
                self.write_output_file(cat_file, list(set(cat_urls)))
                result.output_files[cat_name] = cat_file
                result.stats[f"{cat_name}_count"] = len(set(cat_urls))
                self.logger.info(f"  {cat_name}: {len(set(cat_urls))}")

        # Extract unique parameters
        all_params = set()
        for url in params_urls:
            params = extract_params(url)
            all_params.update(params.keys())

        if all_params:
            params_file = self.output_path / "unique_params.txt"
            self.write_output_file(params_file, sorted(all_params))
            result.output_files["unique_params"] = params_file
            result.stats["unique_params_count"] = len(all_params)

    def _save_json_summary(self, result: ModuleResult) -> None:
        """Save JSON summary."""
        summary = {
            "module": self.name,
            "stats": result.stats,
            "output_files": {k: str(v) for k, v in result.output_files.items()},
            "tools_used": list(self.available_tools),
        }

        json_file = self.output_path / "crawling_summary.json"
        with open(json_file, "w") as f:
            json.dump(summary, f, indent=2)

        result.output_files["json_summary"] = json_file
