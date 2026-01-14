"""
Context Builder for LLM Consumption - Enhanced Version

Consolidates ALL reconnaissance data into one directory for easy LLM access.

Output structure:
  context/
    ├── subdomains.txt            # All discovered subdomains
    ├── live_hosts.txt            # All alive HTTP services
    ├── takeover_vulnerable.txt   # Subdomain takeover vulnerabilities
    ├── all_urls.txt              # All crawled/collected URLs
    ├── urls_with_params.txt      # URLs with parameters (for fuzzing)
    ├── js_files.txt              # JavaScript files
    ├── api_endpoints.txt         # API endpoints
    ├── interesting_urls.txt      # High-value targets
    ├── unique_params.txt         # Unique parameter names
    ├── directories.txt           # Discovered directories (fuzzing)
    ├── sensitive_paths.txt       # Sensitive paths found
    ├── open_ports.txt            # Open ports (host:port)
    ├── dns_records.txt           # DNS enumeration data
    ├── vulnerabilities.txt       # All found vulnerabilities
    ├── secrets.txt               # Potential secrets found
    ├── technologies.json         # Detected technologies
    ├── screenshots/              # Screenshots (symlink or copy)
    ├── consolidated_recon.json   # Full JSON with all data
    └── context_for_llm.json      # Summarized findings for LLM
"""

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from collections import defaultdict

from ..modules.base import ModuleResult
from ..utils.logging import get_logger
from ..utils.dedup import deduplicate_lines
from ..utils.normalize import normalize_url, normalize_domain

logger = get_logger("context_builder")


class ContextBuilder:
    """
    Builds consolidated output and context for LLM consumption.

    ALL reconnaissance data in one place for easy access.
    """

    def __init__(self, output_dir: Path):
        """Initialize the context builder."""
        self.output_dir = output_dir
        self.context_dir = output_dir / "context"
        self.context_dir.mkdir(parents=True, exist_ok=True)

        self.module_results: Dict[str, ModuleResult] = {}
        self.target_info: Dict[str, Any] = {}
        self.scope_info: Dict[str, Any] = {}

    def set_target_info(
        self,
        target_type: str,
        target_value: str,
        targets: List[str],
    ) -> None:
        """Set target information."""
        self.target_info = {
            "type": target_type,
            "primary_target": target_value,
            "total_targets": len(targets),
            "sample_targets": targets[:10],
        }

    def set_scope_info(
        self,
        in_scope: List[str],
        out_of_scope: List[str],
    ) -> None:
        """Set scope information."""
        self.scope_info = {
            "in_scope_rules": len(in_scope),
            "out_of_scope_rules": len(out_of_scope),
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
        }

    def add_module_result(self, result: ModuleResult) -> None:
        """Add a module result."""
        self.module_results[result.module_name] = result

    def build(self) -> Dict[str, Any]:
        """Build all outputs."""
        logger.info("="*60)
        logger.info("Building consolidated output for LLM")
        logger.info("="*60)

        # Build consolidated files (raw data for LLM to test)
        consolidated_files = self._build_consolidated_files()

        # Build JSON summary
        context = self._build_context_summary(consolidated_files)

        # Save consolidated JSON
        self._save_consolidated_json(consolidated_files)

        return context

    def save(self, filename: str = "context_for_llm.json") -> Path:
        """Build and save context."""
        context = self.build()

        output_path = self.context_dir / filename
        with open(output_path, "w") as f:
            json.dump(context, f, indent=2, default=str)

        logger.info(f"Context saved to {output_path}")
        return output_path

    def _build_consolidated_files(self) -> Dict[str, Path]:
        """
        Build consolidated files from ALL module outputs.
        These are the raw files the LLM will use for testing.
        """
        files = {}

        # ===== 1. All Subdomains =====
        subdomains = self._collect_subdomains()
        if subdomains:
            subs_file = self.context_dir / "subdomains.txt"
            subs_file.write_text("\n".join(sorted(subdomains)))
            files["subdomains"] = subs_file
            logger.info(f"  subdomains.txt: {len(subdomains)} entries")

        # ===== 2. Live Hosts (HTTP alive) =====
        live_hosts = self._collect_live_hosts()
        if live_hosts:
            live_file = self.context_dir / "live_hosts.txt"
            live_file.write_text("\n".join(sorted(live_hosts)))
            files["live_hosts"] = live_file
            logger.info(f"  live_hosts.txt: {len(live_hosts)} entries")

        # ===== 3. Subdomain Takeover =====
        takeovers = self._collect_takeovers()
        if takeovers:
            takeover_file = self.context_dir / "takeover_vulnerable.txt"
            takeover_file.write_text("\n".join(takeovers))
            files["takeover_vulnerable"] = takeover_file
            logger.info(f"  takeover_vulnerable.txt: {len(takeovers)} entries")

        # ===== 4. All URLs (crawling + url_collection) =====
        all_urls = self._collect_all_urls()
        if all_urls:
            urls_file = self.context_dir / "all_urls.txt"
            urls_file.write_text("\n".join(all_urls))
            files["all_urls"] = urls_file
            logger.info(f"  all_urls.txt: {len(all_urls)} entries")

        # ===== 5. URLs with Parameters (for fuzzing/injection) =====
        params_urls = self._collect_params_urls()
        if params_urls:
            params_file = self.context_dir / "urls_with_params.txt"
            params_file.write_text("\n".join(params_urls))
            files["urls_with_params"] = params_file
            logger.info(f"  urls_with_params.txt: {len(params_urls)} entries")

        # ===== 6. JavaScript Files =====
        js_files = self._collect_js_files()
        if js_files:
            js_file = self.context_dir / "js_files.txt"
            js_file.write_text("\n".join(js_files))
            files["js_files"] = js_file
            logger.info(f"  js_files.txt: {len(js_files)} entries")

        # ===== 7. API Endpoints =====
        api_endpoints = self._collect_api_endpoints()
        if api_endpoints:
            api_file = self.context_dir / "api_endpoints.txt"
            api_file.write_text("\n".join(api_endpoints))
            files["api_endpoints"] = api_file
            logger.info(f"  api_endpoints.txt: {len(api_endpoints)} entries")

        # ===== 8. Interesting URLs =====
        interesting = self._collect_interesting_urls()
        if interesting:
            int_file = self.context_dir / "interesting_urls.txt"
            int_file.write_text("\n".join(interesting))
            files["interesting_urls"] = int_file
            logger.info(f"  interesting_urls.txt: {len(interesting)} entries")

        # ===== 9. Unique Parameters =====
        params = self._collect_unique_params()
        if params:
            params_names_file = self.context_dir / "unique_params.txt"
            params_names_file.write_text("\n".join(sorted(params)))
            files["unique_params"] = params_names_file
            logger.info(f"  unique_params.txt: {len(params)} entries")

        # ===== 10. Directories (from fuzzing) =====
        directories = self._collect_directories()
        if directories:
            dirs_file = self.context_dir / "directories.txt"
            dirs_file.write_text("\n".join(directories))
            files["directories"] = dirs_file
            logger.info(f"  directories.txt: {len(directories)} entries")

        # ===== 11. Sensitive Paths (from fuzzing) =====
        sensitive = self._collect_sensitive_paths()
        if sensitive:
            sensitive_file = self.context_dir / "sensitive_paths.txt"
            sensitive_file.write_text("\n".join(sensitive))
            files["sensitive_paths"] = sensitive_file
            logger.info(f"  sensitive_paths.txt: {len(sensitive)} entries")

        # ===== 12. Open Ports =====
        open_ports = self._collect_open_ports()
        if open_ports:
            ports_file = self.context_dir / "open_ports.txt"
            ports_file.write_text("\n".join(open_ports))
            files["open_ports"] = ports_file
            logger.info(f"  open_ports.txt: {len(open_ports)} entries")

        # ===== 13. DNS Records =====
        dns_records = self._collect_dns_records()
        if dns_records:
            dns_file = self.context_dir / "dns_records.txt"
            dns_file.write_text("\n".join(dns_records))
            files["dns_records"] = dns_file
            logger.info(f"  dns_records.txt: {len(dns_records)} entries")

        # ===== 14. Vulnerabilities (nuclei, xss, sqli) =====
        vulns = self._collect_vulnerabilities()
        if vulns:
            vulns_file = self.context_dir / "vulnerabilities.txt"
            vulns_file.write_text("\n".join(vulns))
            files["vulnerabilities"] = vulns_file
            logger.info(f"  vulnerabilities.txt: {len(vulns)} entries")

        # ===== 15. Secrets =====
        secrets = self._collect_secrets()
        if secrets:
            secrets_file = self.context_dir / "secrets.txt"
            secrets_file.write_text("\n".join(secrets))
            files["secrets"] = secrets_file
            logger.info(f"  secrets.txt: {len(secrets)} entries")

        # ===== 16. Technologies Detected =====
        technologies = self._collect_technologies()
        if technologies:
            tech_file = self.context_dir / "technologies.json"
            with open(tech_file, "w") as f:
                json.dump(technologies, f, indent=2)
            files["technologies"] = tech_file
            logger.info(f"  technologies.json: {len(technologies)} technologies")

        # ===== 17. Copy/link screenshots =====
        self._consolidate_screenshots(files)

        # ===== 18. Cloud resources =====
        cloud = self._collect_cloud_resources()
        if cloud:
            cloud_file = self.context_dir / "cloud_resources.txt"
            cloud_file.write_text("\n".join(cloud))
            files["cloud_resources"] = cloud_file
            logger.info(f"  cloud_resources.txt: {len(cloud)} entries")

        # ===== 19. Git findings =====
        git_findings = self._collect_git_findings()
        if git_findings:
            git_file = self.context_dir / "git_findings.txt"
            git_file.write_text("\n".join(git_findings))
            files["git_findings"] = git_file
            logger.info(f"  git_findings.txt: {len(git_findings)} entries")

        return files

    # ==================== DATA COLLECTION METHODS ====================

    def _collect_subdomains(self) -> Set[str]:
        """Collect all subdomains from subdomain_enum and passive_sources modules."""
        subdomains = set()

        # From subdomain_enum
        if "subdomain_enum" in self.module_results:
            result = self.module_results["subdomain_enum"]

            # Check multiple output files
            for key in ["all_subdomains", "all_resolved"]:
                if key in result.output_files:
                    f = result.output_files[key]
                    if f.exists():
                        for line in f.read_text().strip().split("\n"):
                            if line.strip():
                                normalized = normalize_domain(line.strip())
                                if normalized:
                                    subdomains.add(normalized)

        # From passive_sources (API-based enumeration)
        if "passive_sources" in self.module_results:
            result = self.module_results["passive_sources"]
            if "all_subdomains" in result.output_files:
                f = result.output_files["all_subdomains"]
                if f.exists():
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            normalized = normalize_domain(line.strip())
                            if normalized:
                                subdomains.add(normalized)

        return subdomains

    def _collect_live_hosts(self) -> Set[str]:
        """Collect all live HTTP hosts."""
        live_hosts = set()

        # From subdomain_enum (alive hosts)
        if "subdomain_enum" in self.module_results:
            result = self.module_results["subdomain_enum"]
            for key in result.output_files:
                if "alive" in key:
                    f = result.output_files[key]
                    if f.exists():
                        for line in f.read_text().strip().split("\n"):
                            if line.strip():
                                live_hosts.add(line.strip())

        # From http_probe
        if "http_probe" in self.module_results:
            result = self.module_results["http_probe"]
            if "alive" in result.output_files:
                f = result.output_files["alive"]
                if f.exists():
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            live_hosts.add(line.strip())

        return live_hosts

    def _collect_takeovers(self) -> List[str]:
        """Collect subdomain takeover vulnerabilities."""
        takeovers = []

        if "subdomain_takeover" in self.module_results:
            result = self.module_results["subdomain_takeover"]

            # Get vulnerable subdomains
            if "vulnerable" in result.output_files:
                f = result.output_files["vulnerable"]
                if f.exists():
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            takeovers.append(f"[VULNERABLE] {line.strip()}")

            # Get potential takeovers
            if "potential" in result.output_files:
                f = result.output_files["potential"]
                if f.exists():
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            takeovers.append(f"[POTENTIAL] {line.strip()}")

        return takeovers

    def _collect_all_urls(self) -> List[str]:
        """Collect all discovered URLs from crawling and url_collection."""
        urls = set()

        # From crawling
        if "crawling" in self.module_results:
            result = self.module_results["crawling"]
            if "all_urls" in result.output_files:
                f = result.output_files["all_urls"]
                if f.exists():
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            urls.add(line.strip())

        # From url_collection
        if "url_collection" in self.module_results:
            result = self.module_results["url_collection"]
            if "all_urls" in result.output_files:
                f = result.output_files["all_urls"]
                if f.exists():
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            urls.add(line.strip())

        return deduplicate_lines(list(urls), normalize_fn=normalize_url)

    def _collect_params_urls(self) -> List[str]:
        """Collect URLs with parameters."""
        params_urls = set()

        modules_to_check = ["crawling", "url_collection", "parameter_discovery"]
        for module_name in modules_to_check:
            if module_name in self.module_results:
                result = self.module_results[module_name]
                for key in result.output_files:
                    if "param" in key.lower() or "with_params" in key.lower():
                        f = result.output_files[key]
                        if f.exists():
                            for line in f.read_text().strip().split("\n"):
                                line = line.strip()
                                if line and "?" in line and "=" in line:
                                    # Clean up any prefixes like "category: "
                                    if ": " in line and not line.startswith("http"):
                                        line = line.split(": ", 1)[-1]
                                    if line.startswith("http"):
                                        params_urls.add(line)

        return deduplicate_lines(list(params_urls), normalize_fn=normalize_url)

    def _collect_js_files(self) -> List[str]:
        """Collect JavaScript file URLs."""
        js_files = set()

        modules_to_check = ["crawling", "url_collection", "js_analysis"]
        for module_name in modules_to_check:
            if module_name in self.module_results:
                result = self.module_results[module_name]
                for key in result.output_files:
                    if "js" in key.lower():
                        f = result.output_files[key]
                        if f.exists():
                            for line in f.read_text().strip().split("\n"):
                                line = line.strip()
                                if line and ".js" in line.lower():
                                    if line.startswith("http"):
                                        js_files.add(line)

        return list(js_files)

    def _collect_api_endpoints(self) -> List[str]:
        """Collect API endpoints."""
        api_endpoints = set()

        modules_to_check = ["crawling", "url_collection", "js_analysis", "fuzzing"]
        for module_name in modules_to_check:
            if module_name in self.module_results:
                result = self.module_results[module_name]
                for key in result.output_files:
                    if "api" in key.lower():
                        f = result.output_files[key]
                        if f.exists():
                            for line in f.read_text().strip().split("\n"):
                                line = line.strip()
                                if line:
                                    # Clean up status codes like "[200] url"
                                    if line.startswith("["):
                                        parts = line.split("] ", 1)
                                        if len(parts) > 1:
                                            line = parts[1]
                                    if line.startswith("http"):
                                        api_endpoints.add(line)

        return list(api_endpoints)

    def _collect_interesting_urls(self) -> List[str]:
        """Collect interesting/high-value URLs."""
        interesting = set()

        # Keywords that indicate interesting targets
        keywords = [
            "admin", "login", "dashboard", "api", "config", "backup",
            "debug", "test", "dev", "staging", "internal", "upload",
            "download", "file", "user", "account", "password", "token",
            "console", "panel", "manage", "phpinfo", "actuator", "swagger",
        ]

        all_urls = self._collect_all_urls()
        for url in all_urls:
            url_lower = url.lower()
            if any(kw in url_lower for kw in keywords):
                interesting.add(url)

        # From crawling interesting category
        if "crawling" in self.module_results:
            result = self.module_results["crawling"]
            if "interesting" in result.output_files:
                f = result.output_files["interesting"]
                if f.exists():
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            interesting.add(line.strip())

        # From url_collection interesting_paths
        if "url_collection" in self.module_results:
            result = self.module_results["url_collection"]
            if "interesting_paths" in result.output_files:
                f = result.output_files["interesting_paths"]
                if f.exists():
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            interesting.add(line.strip())

        # From http_probe interesting hosts
        if "http_probe" in self.module_results:
            result = self.module_results["http_probe"]
            if "interesting_hosts" in result.output_files:
                f = result.output_files["interesting_hosts"]
                if f.exists():
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            interesting.add(line.strip())

        return list(interesting)

    def _collect_unique_params(self) -> Set[str]:
        """Collect unique parameter names."""
        params = set()

        modules_to_check = ["crawling", "url_collection", "parameter_discovery"]
        for module_name in modules_to_check:
            if module_name in self.module_results:
                result = self.module_results[module_name]
                for key in result.output_files:
                    if "unique_params" in key or "param_names" in key:
                        f = result.output_files[key]
                        if f.exists():
                            for line in f.read_text().strip().split("\n"):
                                if line.strip():
                                    params.add(line.strip())

        return params

    def _collect_directories(self) -> List[str]:
        """Collect discovered directories from fuzzing."""
        directories = set()

        if "fuzzing" in self.module_results:
            result = self.module_results["fuzzing"]

            # Get all findings from fuzzing
            for key in result.output_files:
                f = result.output_files[key]
                if f.exists() and f.suffix == ".txt":
                    for line in f.read_text().strip().split("\n"):
                        line = line.strip()
                        if line and ("http" in line or line.startswith("/")):
                            directories.add(line)

        return sorted(list(directories))

    def _collect_sensitive_paths(self) -> List[str]:
        """Collect sensitive paths from fuzzing."""
        paths = set()

        if "fuzzing" in self.module_results:
            result = self.module_results["fuzzing"]
            for key in result.output_files:
                if "sensitive" in key.lower() or "backup" in key.lower():
                    f = result.output_files[key]
                    if f.exists():
                        for line in f.read_text().strip().split("\n"):
                            if line.strip():
                                paths.add(line.strip())

        return list(paths)

    def _collect_open_ports(self) -> List[str]:
        """Collect open ports from port scan."""
        ports = []

        if "port_scan" in self.module_results:
            result = self.module_results["port_scan"]
            if "open_ports" in result.output_files:
                f = result.output_files["open_ports"]
                if f.exists():
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            ports.append(line.strip())

        return ports

    def _collect_dns_records(self) -> List[str]:
        """Collect DNS enumeration data."""
        records = []

        if "dns_enum" in self.module_results:
            result = self.module_results["dns_enum"]

            # Get all DNS record types
            for key in result.output_files:
                f = result.output_files[key]
                if f.exists() and f.suffix in [".txt", ".json"]:
                    if f.suffix == ".json":
                        try:
                            data = json.loads(f.read_text())
                            for record_type, values in data.items():
                                if isinstance(values, list):
                                    for v in values:
                                        records.append(f"[{record_type}] {v}")
                        except:
                            pass
                    else:
                        for line in f.read_text().strip().split("\n"):
                            if line.strip():
                                records.append(line.strip())

        return records

    def _collect_vulnerabilities(self) -> List[str]:
        """Collect found vulnerabilities from all scan modules."""
        vulns = []

        # From nuclei_scan
        if "nuclei_scan" in self.module_results:
            result = self.module_results["nuclei_scan"]

            # Try to read from all_findings or severity-based files
            if "all_findings" in result.output_files:
                f = result.output_files["all_findings"]
                if f.exists():
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            vulns.append(line.strip())
            else:
                # Try severity-based files
                for severity in ["critical", "high", "medium", "low", "info"]:
                    if severity in result.output_files:
                        f = result.output_files[severity]
                        if f.exists():
                            for line in f.read_text().strip().split("\n"):
                                if line.strip():
                                    vulns.append(f"[{severity.upper()}] {line.strip()}")

                # Fall back to findings from result
                if not vulns:
                    for finding in result.findings:
                        vuln_str = f"[{finding.get('severity', 'unknown').upper()}] {finding.get('template', 'unknown')}: {finding.get('url', '')}"
                        vulns.append(vuln_str)

        # From xss_scan
        if "xss_scan" in self.module_results:
            result = self.module_results["xss_scan"]
            for finding in result.findings:
                vuln_str = f"[XSS] {finding.get('url', '')} - param: {finding.get('param', '')}"
                vulns.append(vuln_str)

            # Also check output files
            for key in result.output_files:
                f = result.output_files[key]
                if f.exists() and "xss" in key.lower():
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            vulns.append(f"[XSS] {line.strip()}")

        # From sqli_scan
        if "sqli_scan" in self.module_results:
            result = self.module_results["sqli_scan"]
            for finding in result.findings:
                vuln_str = f"[SQLi] {finding.get('url', '')}"
                vulns.append(vuln_str)

        # From subdomain_takeover
        if "subdomain_takeover" in self.module_results:
            result = self.module_results["subdomain_takeover"]
            for finding in result.findings:
                vuln_str = f"[TAKEOVER] {finding.get('subdomain', '')}"
                vulns.append(vuln_str)

        # From cors_check
        if "cors_check" in self.module_results:
            result = self.module_results["cors_check"]
            for finding in result.findings:
                vuln_str = f"[CORS] {finding.get('url', '')} - {finding.get('test', '')}"
                vulns.append(vuln_str)

            # Also check output files
            if "vulnerable" in result.output_files:
                f = result.output_files["vulnerable"]
                if f.exists():
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            vulns.append(f"[CORS] {line.strip()}")

        # From vuln_patterns (LFI, SSRF, Open Redirect, SSTI)
        if "vuln_patterns" in self.module_results:
            result = self.module_results["vuln_patterns"]
            for finding in result.findings:
                vuln_type = finding.get("type", "unknown").upper()
                vuln_str = f"[{vuln_type}] {finding.get('url', '')}"
                vulns.append(vuln_str)

            # Also check output files
            for vuln_type in ["lfi", "ssrf", "redirect", "ssti"]:
                key = f"{vuln_type}_vulnerable" if f"{vuln_type}_vulnerable" in result.output_files else vuln_type
                if key in result.output_files:
                    f = result.output_files[key]
                    if f.exists():
                        for line in f.read_text().strip().split("\n"):
                            if line.strip():
                                vulns.append(f"[{vuln_type.upper()}] {line.strip()}")

        return list(set(vulns))  # Deduplicate

    def _collect_secrets(self) -> List[str]:
        """Collect potential secrets found."""
        secrets = []

        if "js_analysis" in self.module_results:
            result = self.module_results["js_analysis"]
            if "secrets" in result.output_files:
                f = result.output_files["secrets"]
                if f.exists():
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            secrets.append(line.strip())

        if "git_recon" in self.module_results:
            result = self.module_results["git_recon"]
            for finding in result.findings:
                if "secret" in finding.get("type", "").lower():
                    secrets.append(f"[GIT] {finding.get('value', '')[:100]}")

        return secrets

    def _collect_technologies(self) -> Dict[str, int]:
        """Collect detected technologies."""
        technologies = {}

        if "http_probe" in self.module_results:
            result = self.module_results["http_probe"]
            if "technologies" in result.metadata:
                technologies = result.metadata["technologies"]
            elif "technologies" in result.output_files:
                f = result.output_files["technologies"]
                if f.exists():
                    try:
                        data = json.loads(f.read_text())
                        technologies = data.get("technologies", {})
                    except:
                        pass

        return technologies

    def _collect_cloud_resources(self) -> List[str]:
        """Collect cloud resource findings."""
        resources = []

        if "cloud_enum" in self.module_results:
            result = self.module_results["cloud_enum"]
            for key in result.output_files:
                f = result.output_files[key]
                if f.exists() and f.suffix == ".txt":
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            resources.append(line.strip())

        # Also check js_analysis for S3 buckets
        if "js_analysis" in self.module_results:
            result = self.module_results["js_analysis"]
            for finding in result.findings:
                if "s3" in finding.get("type", "").lower():
                    resources.append(f"[S3] {finding.get('value', '')}")

        return list(set(resources))

    def _collect_git_findings(self) -> List[str]:
        """Collect git-related findings."""
        findings = []

        if "git_recon" in self.module_results:
            result = self.module_results["git_recon"]
            for key in result.output_files:
                f = result.output_files[key]
                if f.exists() and f.suffix == ".txt":
                    for line in f.read_text().strip().split("\n"):
                        if line.strip():
                            findings.append(line.strip())

        return findings

    def _consolidate_screenshots(self, files: Dict[str, Path]) -> None:
        """Consolidate screenshots into context directory."""
        screenshots_dir = self.context_dir / "screenshots"

        if "screenshots" in self.module_results:
            result = self.module_results["screenshots"]

            # Check for screenshots directory in the module output
            source_dir = self.output_dir / "screenshots"
            if source_dir.exists() and source_dir.is_dir():
                # Create symlink or copy
                if not screenshots_dir.exists():
                    try:
                        screenshots_dir.symlink_to(source_dir)
                        files["screenshots"] = screenshots_dir
                        logger.info(f"  screenshots/: linked")
                    except:
                        # Fall back to copying
                        shutil.copytree(source_dir, screenshots_dir, dirs_exist_ok=True)
                        files["screenshots"] = screenshots_dir
                        logger.info(f"  screenshots/: copied")

    # ==================== JSON BUILDERS ====================

    def _save_consolidated_json(self, files: Dict[str, Path]) -> None:
        """Save consolidated JSON with all data."""
        consolidated = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "recon_tool_version": "1.0.0",
                "modules_executed": list(self.module_results.keys()),
                "total_modules": len(self.module_results),
                "successful_modules": len([r for r in self.module_results.values() if r.success]),
            },
            "target": self.target_info,
            "scope": self.scope_info,
            "statistics": {},
            "files": {},
            "data": {},
            "attack_surface": {},
            "high_risk_findings": [],
        }

        # Add statistics from each module
        for module_name, result in self.module_results.items():
            consolidated["statistics"][module_name] = result.stats

        # Add file paths
        for name, path in files.items():
            consolidated["files"][name] = str(path)

        # Add attack surface summary
        consolidated["attack_surface"] = {
            "subdomains": len(self._collect_subdomains()),
            "live_hosts": len(self._collect_live_hosts()),
            "takeover_vulnerable": len(self._collect_takeovers()),
            "total_urls": len(self._collect_all_urls()),
            "urls_with_params": len(self._collect_params_urls()),
            "js_files": len(self._collect_js_files()),
            "api_endpoints": len(self._collect_api_endpoints()),
            "interesting_urls": len(self._collect_interesting_urls()),
            "directories": len(self._collect_directories()),
            "open_ports": len(self._collect_open_ports()),
            "unique_params": len(self._collect_unique_params()),
            "vulnerabilities": len(self._collect_vulnerabilities()),
            "secrets": len(self._collect_secrets()),
        }

        # Add high-risk findings
        for module_name, result in self.module_results.items():
            for finding in result.findings:
                severity = finding.get("severity", "").lower()
                if severity in ["critical", "high"]:
                    consolidated["high_risk_findings"].append({
                        "module": module_name,
                        **finding,
                    })

        # Limit high risk findings
        consolidated["high_risk_findings"] = consolidated["high_risk_findings"][:100]

        # Add inline data for important files
        for name, path in files.items():
            if path.exists() and path.is_file():
                if path.suffix == ".json":
                    try:
                        consolidated["data"][name] = json.loads(path.read_text())
                    except:
                        pass
                else:
                    lines = path.read_text().strip().split("\n")
                    lines = [l for l in lines if l]  # Filter empty

                    # Include full data for important small files
                    if name in ["urls_with_params", "api_endpoints", "interesting_urls",
                               "vulnerabilities", "secrets", "sensitive_paths",
                               "takeover_vulnerable", "cloud_resources", "git_findings"]:
                        consolidated["data"][name] = lines
                    else:
                        # Include count and sample for large files
                        consolidated["data"][name] = {
                            "count": len(lines),
                            "sample": lines[:100] if len(lines) > 100 else lines,
                        }

        # Save
        json_file = self.context_dir / "consolidated_recon.json"
        with open(json_file, "w") as f:
            json.dump(consolidated, f, indent=2)

        logger.info(f"Consolidated JSON saved to {json_file}")

    def _build_context_summary(self, files: Dict[str, Path]) -> Dict[str, Any]:
        """Build summarized context for LLM analysis."""
        return {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "recon_tool_version": "1.0.0",
                "modules_executed": list(self.module_results.keys()),
                "total_modules": len(self.module_results),
                "successful_modules": len([r for r in self.module_results.values() if r.success]),
            },
            "target": self.target_info,
            "scope": self.scope_info,
            "statistics": self._build_statistics(),
            "attack_surface": self._build_attack_surface(),
            "high_risk_findings": self._build_high_risk_findings(),
            "secrets_indicators": self._build_secrets_summary(),
            "interesting_parameters": self._build_interesting_params(),
            "technology_stack": self._build_technology_stack(),
            "correlations": self._build_correlations(),
            "recommendations": self._build_recommendations(),
            "output_files": {name: str(path) for name, path in files.items()},
        }

    def _build_statistics(self) -> Dict[str, Any]:
        """Build statistics summary."""
        stats = {}
        for module_name, result in self.module_results.items():
            stats[module_name] = result.stats
        return stats

    def _build_attack_surface(self) -> Dict[str, Any]:
        """Build attack surface summary."""
        return {
            "exposed_services": list(self._collect_live_hosts())[:20],
            "api_endpoints": list(self._collect_api_endpoints())[:20],
            "interesting_paths": list(self._collect_interesting_urls())[:20],
            "takeover_vulnerable": self._collect_takeovers()[:10],
            "input_vectors": [
                {"url": url, "param": url.split("?")[1].split("=")[0] if "?" in url else ""}
                for url in list(self._collect_params_urls())[:10]
            ],
        }

    def _build_high_risk_findings(self) -> List[Dict[str, Any]]:
        """Build high-risk findings list."""
        findings = []
        for module_name, result in self.module_results.items():
            for finding in result.findings:
                severity = finding.get("severity", "").lower()
                if severity in ["critical", "high"]:
                    findings.append({
                        "module": module_name,
                        **finding,
                    })
        return findings[:50]

    def _build_secrets_summary(self) -> List[Dict[str, str]]:
        """Build secrets summary."""
        secrets = self._collect_secrets()
        return [{"source": "analysis", "indicator": s[:100]} for s in secrets[:10]]

    def _build_interesting_params(self) -> List[Dict[str, str]]:
        """Build interesting parameters summary."""
        params_urls = self._collect_params_urls()
        result = []

        interesting_patterns = ["id", "user", "admin", "token", "key", "file", "path", "url", "redirect", "cmd"]

        for url in params_urls[:20]:
            if "?" in url:
                params_part = url.split("?")[1]
                for param in params_part.split("&"):
                    if "=" in param:
                        param_name = param.split("=")[0].lower()
                        if any(p in param_name for p in interesting_patterns):
                            result.append({"url": url, "param": param.split("=")[0]})
                            break

        return result[:20]

    def _build_technology_stack(self) -> Dict[str, Any]:
        """Build technology stack summary."""
        technologies = self._collect_technologies()

        result = {
            "web_technologies": dict(sorted(technologies.items(), key=lambda x: x[1], reverse=True)[:15]),
            "server_software": [],
        }

        if "http_probe" in self.module_results:
            result_data = self.module_results["http_probe"]
            if "server_software" in result_data.metadata:
                result["server_software"] = list(result_data.metadata["server_software"].keys())[:10]

        return result

    def _build_correlations(self) -> List[Dict[str, Any]]:
        """Build correlations between findings."""
        correlations = []

        # Find hosts with both open ports and vulnerabilities
        open_ports_data = {}
        if "port_scan" in self.module_results:
            result = self.module_results["port_scan"]
            open_ports_data = result.metadata.get("hosts_ports", {})

        # Find hosts with critical vulnerabilities
        critical_hosts = set()
        if "nuclei_scan" in self.module_results:
            result = self.module_results["nuclei_scan"]
            for finding in result.findings:
                if finding.get("severity", "").lower() in ["critical", "high"]:
                    url = finding.get("url", "")
                    if url:
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        if parsed.hostname:
                            critical_hosts.add(parsed.hostname)

        # Find hosts vulnerable to takeover
        takeover_hosts = set()
        if "subdomain_takeover" in self.module_results:
            result = self.module_results["subdomain_takeover"]
            for finding in result.findings:
                subdomain = finding.get("subdomain", "")
                if subdomain:
                    takeover_hosts.add(subdomain)

        # Correlate
        for host in critical_hosts:
            if host in open_ports_data:
                correlations.append({
                    "type": "critical_vulnerability_host",
                    "host": host,
                    "ports": [str(p) for p in open_ports_data[host]],
                    "insight": "Host with critical vulnerabilities - prioritize",
                })

        for host in takeover_hosts:
            correlations.append({
                "type": "subdomain_takeover",
                "host": host,
                "insight": "Subdomain vulnerable to takeover - HIGH PRIORITY",
            })

        # Find hosts with sensitive ports
        sensitive_ports = {"3306", "5432", "27017", "6379", "11211", "445", "23"}
        for host, ports in open_ports_data.items():
            host_sensitive = [str(p) for p in ports if str(p) in sensitive_ports]
            if host_sensitive:
                correlations.append({
                    "type": "subdomain_with_sensitive_port",
                    "host": host,
                    "ports": host_sensitive,
                    "insight": f"Host with sensitive ports: {', '.join(host_sensitive)}",
                })

        return correlations[:20]

    def _build_recommendations(self) -> List[str]:
        """Build actionable recommendations."""
        recommendations = []

        # Check for takeovers
        takeovers = self._collect_takeovers()
        if takeovers:
            vulnerable = [t for t in takeovers if "VULNERABLE" in t]
            if vulnerable:
                recommendations.append(f"CRITICAL: {len(vulnerable)} subdomain takeover vulnerabilities found. Immediate action required!")

        # Check for vulnerabilities
        vulns = self._collect_vulnerabilities()
        if vulns:
            critical = len([v for v in vulns if "CRITICAL" in v.upper()])
            high = len([v for v in vulns if "HIGH" in v.upper()])
            if critical:
                recommendations.append(f"URGENT: {critical} critical vulnerabilities found. Review and remediate immediately.")
            if high:
                recommendations.append(f"HIGH: {high} high-severity vulnerabilities require attention.")

        # Check for secrets
        secrets = self._collect_secrets()
        if secrets:
            recommendations.append(f"SECRETS: {len(secrets)} potential secrets exposed. Rotate credentials and implement secret management.")

        # Check for params URLs
        params = self._collect_params_urls()
        if params:
            recommendations.append(f"Test {len(params)} URLs with parameters for injection vulnerabilities (SQLi, XSS, etc.)")

        # Check for API endpoints
        apis = self._collect_api_endpoints()
        if apis:
            recommendations.append(f"Review {len(apis)} API endpoints for authentication/authorization issues")

        # Check for sensitive paths
        sensitive = self._collect_sensitive_paths()
        if sensitive:
            recommendations.append(f"EXPOSURE: {len(sensitive)} sensitive paths found. Review access controls.")

        # Check attack surface size
        live_hosts = self._collect_live_hosts()
        if len(live_hosts) > 50:
            recommendations.append("Large attack surface detected. Consider network segmentation and reducing exposed services.")

        return recommendations
