"""
JavaScript Analysis Module - Enhanced Version

Analyzes JavaScript files to discover:
- API endpoints and URLs
- Secrets and sensitive data
- Hidden functionality

Tools:
- subjs
- linkfinder
- secretfinder
- jsubfinder

Output structure:
  js/
    ├── raw/
    │   ├── linkfinder.txt
    │   ├── secretfinder.txt
    │   ├── subjs.txt
    │   └── jsubfinder.txt
    ├── endpoints.txt (all discovered endpoints)
    ├── secrets.txt (all potential secrets)
    ├── api_endpoints.txt
    ├── internal_endpoints.txt
    ├── s3_buckets.txt
    ├── domains_found.txt
    └── js_analysis_summary.json
"""

import json
import re
import time
from pathlib import Path
from typing import List, Optional, Dict, Any, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import PassiveModule, ModuleResult
from ..utils.process import ToolResult, check_tool_exists
from ..utils.dedup import deduplicate_lines


class JsAnalysisModule(PassiveModule):
    """Enhanced JavaScript file analysis for secrets and endpoint discovery."""

    name = "js_analysis"
    description = "Analyze JavaScript files for endpoints, secrets, and sensitive data"
    tools = ["subjs", "linkfinder", "secretfinder", "jsubfinder"]
    output_dir = "js"

    # Patterns for manual secret detection
    SECRET_PATTERNS = {
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "aws_secret_key": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
        "google_api_key": r"AIza[0-9A-Za-z-_]{35}",
        "google_oauth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "github_token": r"gh[ps]_[0-9a-zA-Z]{36}",
        "github_oauth": r"gho_[0-9a-zA-Z]{36}",
        "slack_token": r"xox[baprs]-[0-9a-zA-Z-]{10,}",
        "slack_webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "jwt_token": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*",
        "private_key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "password_field": r"[\"']password[\"']\s*[:=]\s*[\"'][^\"']{4,}[\"']",
        "api_key_field": r"[\"']api[_-]?key[\"']\s*[:=]\s*[\"'][^\"']{8,}[\"']",
        "secret_field": r"[\"']secret[\"']\s*[:=]\s*[\"'][^\"']{8,}[\"']",
        "bearer_token": r"[Bb]earer\s+[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*",
        "firebase_url": r"https://[a-z0-9-]+\.firebaseio\.com",
        "firebase_api": r"AIza[0-9A-Za-z-_]{35}",
        "stripe_key": r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}",
        "heroku_api": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "mailgun_key": r"key-[0-9a-zA-Z]{32}",
        "twilio_sid": r"AC[a-zA-Z0-9_-]{32}",
        "twilio_token": r"SK[a-zA-Z0-9_-]{32}",
        "sendgrid_key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "square_token": r"sq0[a-z]{3}-[0-9A-Za-z-_]{22,}",
        "shopify_token": r"shppa_[a-fA-F0-9]{32}",
        "npm_token": r"npm_[A-Za-z0-9]{36}",
    }

    # Patterns for S3 buckets
    S3_PATTERNS = [
        r"[a-zA-Z0-9.-]+\.s3\.amazonaws\.com",
        r"[a-zA-Z0-9.-]+\.s3-[a-z0-9-]+\.amazonaws\.com",
        r"s3\.amazonaws\.com/[a-zA-Z0-9.-]+",
        r"s3://[a-zA-Z0-9.-]+",
        r"arn:aws:s3:::[a-zA-Z0-9.-]+",
    ]

    # Patterns for domains/URLs in JS
    URL_PATTERNS = [
        r"https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+[/a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=-]*",
        r"[\"'](\/[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=-]+)[\"']",
    ]

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        **kwargs,
    ) -> ModuleResult:
        """
        Analyze JavaScript files.

        Args:
            targets: List of JS URLs to analyze
            resume: Skip if output exists
            input_file: File containing JS URLs

        Returns:
            ModuleResult with discovered endpoints and secrets
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

        # Load targets (should be JS file URLs)
        if input_file and input_file.exists():
            targets = self.read_input_file(input_file)

        # Filter to only JS files
        js_targets = [t for t in targets if ".js" in t.lower() and "?" not in t.split(".js")[-1][:5]]

        if not js_targets:
            self.logger.warning("No JavaScript files to analyze")
            result.duration = time.time() - start_time
            return result

        # Filter by scope
        js_targets = self.filter_scope(js_targets)
        js_targets = list(set(js_targets))

        self.logger.info(f"{'='*50}")
        self.logger.info(f"Analyzing {len(js_targets)} JavaScript files")
        self.logger.info(f"{'='*50}")

        # Write targets
        targets_file = self.output_path / "js_targets.txt"
        self.write_output_file(targets_file, js_targets)

        # Output files
        endpoints_output = self.output_path / "endpoints.txt"
        secrets_output = self.output_path / "secrets.txt"

        if resume and endpoints_output.exists() and endpoints_output.stat().st_size > 0:
            self.logger.info("Resuming: Using existing JS analysis results")
            result.duration = time.time() - start_time
            return result

        all_endpoints: Set[str] = set()
        all_secrets: List[Dict] = []
        all_s3_buckets: Set[str] = set()
        all_domains: Set[str] = set()

        # Run tools in parallel
        tool_outputs = self._run_tools_parallel(
            js_targets, raw_dir, result
        )

        # Collect endpoints from tool outputs
        for tool_name, output_file in tool_outputs.items():
            if output_file.exists():
                lines = self.read_input_file(output_file)
                if tool_name in ["linkfinder", "subjs"]:
                    all_endpoints.update(lines)
                elif tool_name in ["secretfinder", "jsubfinder"]:
                    for line in lines:
                        if line.strip():
                            all_secrets.append({
                                "source": tool_name,
                                "value": line.strip()[:500],  # Truncate
                            })

                result.stats[f"{tool_name}_count"] = len(lines)
                self.logger.info(f"  {tool_name}: {len(lines)} findings")

        # Manual pattern matching for additional secrets and endpoints
        self.logger.info("Running pattern-based analysis...")
        manual_results = self._analyze_js_content(js_targets)
        all_secrets.extend(manual_results["secrets"])
        all_s3_buckets.update(manual_results["s3_buckets"])
        all_domains.update(manual_results["domains"])
        all_endpoints.update(manual_results["endpoints"])

        # Deduplicate and save endpoints
        if all_endpoints:
            endpoints_list = deduplicate_lines(list(all_endpoints))
            self.write_output_file(endpoints_output, endpoints_list)
            result.output_files["endpoints"] = endpoints_output
            result.stats["endpoints_count"] = len(endpoints_list)

            # Categorize endpoints
            self._categorize_endpoints(endpoints_list, result)

        # Save secrets
        if all_secrets:
            # Deduplicate secrets by value
            seen_values = set()
            unique_secrets = []
            for s in all_secrets:
                val = s.get("value", "")
                if val and val not in seen_values:
                    seen_values.add(val)
                    unique_secrets.append(s)

            secrets_lines = [f"{s.get('source', 'unknown')}: {s.get('value', '')}" for s in unique_secrets]
            self.write_output_file(secrets_output, secrets_lines)
            result.output_files["secrets"] = secrets_output
            result.stats["secrets_count"] = len(unique_secrets)

            # Add as findings (high severity)
            for secret in unique_secrets[:30]:
                result.findings.append({
                    "type": "potential_secret",
                    "source": secret.get("source", "pattern_match"),
                    "value": secret.get("value", "")[:200],
                    "severity": "high",
                })

            self.logger.warning(f"Found {len(unique_secrets)} potential secrets!")

        # Save S3 buckets
        if all_s3_buckets:
            s3_file = self.output_path / "s3_buckets.txt"
            self.write_output_file(s3_file, list(all_s3_buckets))
            result.output_files["s3_buckets"] = s3_file
            result.stats["s3_buckets_count"] = len(all_s3_buckets)

            for bucket in list(all_s3_buckets)[:10]:
                result.findings.append({
                    "type": "s3_bucket",
                    "value": bucket,
                    "severity": "medium",
                })

        # Save domains found
        if all_domains:
            domains_file = self.output_path / "domains_found.txt"
            self.write_output_file(domains_file, list(all_domains))
            result.output_files["domains_found"] = domains_file
            result.stats["domains_found_count"] = len(all_domains)

        self.logger.info(
            f"Found {len(all_endpoints)} endpoints, {len(all_secrets)} secrets, "
            f"{len(all_s3_buckets)} S3 buckets, {len(all_domains)} domains"
        )

        # Save JSON summary
        self._save_json_summary(result)

        result.duration = time.time() - start_time
        return result

    def _run_tools_parallel(
        self,
        js_targets: List[str],
        raw_dir: Path,
        result: ModuleResult,
    ) -> Dict[str, Path]:
        """Run JS analysis tools in parallel."""
        tool_outputs = {}

        tools = [
            ("linkfinder", self._run_linkfinder),
            ("secretfinder", self._run_secretfinder),
            ("subjs", self._run_subjs),
            ("jsubfinder", self._run_jsubfinder),
        ]

        targets_file = self.output_path / "js_targets.txt"

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {}

            for tool_name, tool_func in tools:
                if check_tool_exists(tool_name):
                    output_file = raw_dir / f"{tool_name}.txt"
                    future = executor.submit(tool_func, targets_file, output_file, js_targets)
                    futures[future] = (tool_name, output_file)

            for future in as_completed(futures):
                tool_name, output_file = futures[future]
                try:
                    tool_result = future.result()
                    if tool_result:
                        result.add_tool_result(tool_result)
                    if output_file.exists():
                        tool_outputs[tool_name] = output_file
                except Exception as e:
                    self.logger.error(f"Error running {tool_name}: {e}")

        return tool_outputs

    def _run_linkfinder(self, input_file: Path, output_file: Path, js_urls: List[str]) -> Optional[ToolResult]:
        """Run linkfinder for endpoint extraction."""
        all_endpoints = []

        for url in js_urls[:100]:  # Limit to prevent slowness
            args = ["-i", url, "-o", "cli"]
            result = self.run_tool("linkfinder", args, timeout=30)
            if result.success and result.stdout:
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("[") and not line.startswith("Running"):
                        all_endpoints.append(line)

        if all_endpoints:
            output_file.write_text("\n".join(list(set(all_endpoints))))

        return None  # Don't add individual results

    def _run_secretfinder(self, input_file: Path, output_file: Path, js_urls: List[str]) -> Optional[ToolResult]:
        """Run secretfinder for secret detection."""
        all_secrets = []

        for url in js_urls[:100]:
            args = ["-i", url, "-o", "cli"]
            result = self.run_tool("secretfinder", args, timeout=30)
            if result.success and result.stdout:
                all_secrets.append(f"=== {url} ===")
                all_secrets.append(result.stdout)

        if all_secrets:
            output_file.write_text("\n".join(all_secrets))

        return None

    def _run_subjs(self, input_file: Path, output_file: Path, js_urls: List[str]) -> Optional[ToolResult]:
        """Run subjs for JS URL discovery from pages."""
        input_data = input_file.read_text()
        args = []
        return self.run_tool(
            "subjs",
            args,
            input_data=input_data,
            output_file=output_file,
            timeout=300,
        )

    def _run_jsubfinder(self, input_file: Path, output_file: Path, js_urls: List[str]) -> Optional[ToolResult]:
        """Run jsubfinder for secret and subdomain discovery."""
        args = ["-f", str(input_file), "-s"]
        return self.run_tool(
            "jsubfinder",
            args,
            output_file=output_file,
            timeout=300,
        )

    def _analyze_js_content(self, js_urls: List[str]) -> Dict[str, Any]:
        """Analyze JS content using regex patterns."""
        results = {
            "secrets": [],
            "s3_buckets": set(),
            "domains": set(),
            "endpoints": set(),
        }

        # This would require downloading JS content
        # For now, we'll just extract info from URLs
        for url in js_urls:
            # Extract domain
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.netloc:
                    results["domains"].add(parsed.netloc)
            except:
                pass

        return results

    def _categorize_endpoints(self, endpoints: List[str], result: ModuleResult) -> None:
        """Categorize discovered endpoints."""
        api_endpoints = []
        internal_endpoints = []
        auth_endpoints = []
        admin_endpoints = []

        for endpoint in endpoints:
            endpoint_lower = endpoint.lower()

            if any(p in endpoint_lower for p in ["/api/", "/v1/", "/v2/", "/v3/", "graphql", "/rest/"]):
                api_endpoints.append(endpoint)

            if any(p in endpoint_lower for p in ["internal", "private", "hidden", "_internal"]):
                internal_endpoints.append(endpoint)

            if any(p in endpoint_lower for p in ["login", "auth", "oauth", "token", "session", "password"]):
                auth_endpoints.append(endpoint)

            if any(p in endpoint_lower for p in ["admin", "dashboard", "manage", "control", "config"]):
                admin_endpoints.append(endpoint)

        # Write categorized files
        categories = {
            "api_endpoints": api_endpoints,
            "internal_endpoints": internal_endpoints,
            "auth_endpoints": auth_endpoints,
            "admin_endpoints": admin_endpoints,
        }

        for cat_name, cat_endpoints in categories.items():
            if cat_endpoints:
                cat_file = self.output_path / f"{cat_name}.txt"
                self.write_output_file(cat_file, list(set(cat_endpoints)))
                result.output_files[cat_name] = cat_file
                result.stats[f"{cat_name}_count"] = len(set(cat_endpoints))

        # Flag interesting findings
        for ep in internal_endpoints[:10]:
            result.findings.append({
                "type": "internal_endpoint",
                "value": ep,
                "severity": "medium",
            })

        for ep in admin_endpoints[:10]:
            result.findings.append({
                "type": "admin_endpoint",
                "value": ep,
                "severity": "medium",
            })

    def _save_json_summary(self, result: ModuleResult) -> None:
        """Save JSON summary."""
        summary = {
            "module": self.name,
            "stats": result.stats,
            "output_files": {k: str(v) for k, v in result.output_files.items()},
            "tools_used": list(self.available_tools),
            "findings_count": len(result.findings),
            "high_severity_findings": len([f for f in result.findings if f.get("severity") == "high"]),
        }

        json_file = self.output_path / "js_analysis_summary.json"
        with open(json_file, "w") as f:
            json.dump(summary, f, indent=2)

        result.output_files["json_summary"] = json_file
