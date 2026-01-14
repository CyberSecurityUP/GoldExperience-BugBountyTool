"""
HTTP Probing Module - Enhanced Version

Probes discovered hosts to identify live HTTP services:
- httpx (primary - with tech detection)
- httprobe (secondary)

Output structure:
  http/
    ├── raw/
    │   ├── httpx.txt
    │   ├── httpx.jsonl
    │   └── httprobe.txt
    ├── alive.txt (merged live hosts)
    ├── by_status/
    │   ├── 200.txt
    │   ├── 301.txt
    │   ├── 403.txt
    │   └── ...
    ├── technologies.json
    ├── interesting_hosts.txt
    └── http_probe_summary.json
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import ActiveModule, ModuleResult
from ..utils.process import ToolResult, check_tool_exists
from ..utils.dedup import merge_files, deduplicate_lines


class HttpProbeModule(ActiveModule):
    """Enhanced HTTP probing with categorized output."""

    name = "http_probe"
    description = "Probe hosts for live HTTP/HTTPS services with technology detection"
    tools = ["httpx", "httprobe"]
    output_dir = "http"

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        **kwargs,
    ) -> ModuleResult:
        """
        Run HTTP probing on targets.

        Args:
            targets: List of hosts/subdomains to probe
            resume: Skip if output exists
            input_file: Optional file containing targets

        Returns:
            ModuleResult with live HTTP services and metadata
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
        status_dir = self.output_path / "by_status"
        status_dir.mkdir(parents=True, exist_ok=True)

        # Prepare input
        if input_file and input_file.exists():
            targets = self.read_input_file(input_file)

        if not targets:
            self.logger.warning("No targets provided for HTTP probing")
            result.success = False
            result.errors.append("No targets provided")
            result.duration = time.time() - start_time
            return result

        # Filter by scope
        targets = self.filter_scope(targets)
        targets = self.deduplicate(targets)

        self.logger.info(f"{'='*50}")
        self.logger.info(f"Probing {len(targets)} targets for HTTP services")
        self.logger.info(f"{'='*50}")

        # Write targets to temp file for tools
        targets_file = self.output_path / "targets.txt"
        self.write_output_file(targets_file, targets)

        # Output files
        alive_output = self.output_path / "alive.txt"

        if resume and alive_output.exists() and alive_output.stat().st_size > 0:
            self.logger.info("Resuming: Using existing HTTP probe results")
            urls = self.read_input_file(alive_output)
            result.stats["alive_count"] = len(urls)
            result.duration = time.time() - start_time
            return result

        tool_outputs = []

        # Run httpx (preferred - provides more data)
        if check_tool_exists("httpx"):
            httpx_output = raw_dir / "httpx.txt"
            httpx_json = raw_dir / "httpx.jsonl"
            httpx_result = self._run_httpx(targets_file, httpx_output, httpx_json)
            result.add_tool_result(httpx_result)

            if httpx_result.success and httpx_output.exists():
                tool_outputs.append(httpx_output)
                result.output_files["httpx"] = httpx_output
                result.output_files["httpx_json"] = httpx_json

                # Parse httpx JSON for additional data
                self._parse_httpx_json(httpx_json, status_dir, result)

                count = len(self.read_input_file(httpx_output))
                result.stats["httpx_count"] = count
                self.logger.info(f"  httpx: {count} alive hosts")

        # Run httprobe as backup/supplement
        if check_tool_exists("httprobe"):
            httprobe_output = raw_dir / "httprobe.txt"
            httprobe_result = self._run_httprobe(targets_file, httprobe_output)
            result.add_tool_result(httprobe_result)

            if httprobe_result.success and httprobe_output.exists():
                tool_outputs.append(httprobe_output)
                result.output_files["httprobe"] = httprobe_output

                count = len(self.read_input_file(httprobe_output))
                result.stats["httprobe_count"] = count
                self.logger.info(f"  httprobe: {count} alive hosts")

        # Merge results
        if tool_outputs:
            all_alive = []
            for f in tool_outputs:
                if f.exists():
                    all_alive.extend(self.read_input_file(f))

            all_alive = deduplicate_lines(all_alive)
            all_alive = self.filter_scope(all_alive)
            self.write_output_file(alive_output, all_alive)

            result.output_files["alive"] = alive_output
            result.stats["alive_count"] = len(all_alive)
            self.logger.info(f"Total unique alive hosts: {len(all_alive)}")

        # Save JSON summary
        self._save_json_summary(result)

        result.duration = time.time() - start_time
        return result

    def _run_httpx(
        self,
        input_file: Path,
        output_file: Path,
        json_file: Path,
    ) -> ToolResult:
        """Run httpx for HTTP probing with detailed output."""
        args = [
            "-l", str(input_file),
            "-o", str(output_file),
            "-jsonl",
            "-output", str(json_file),
            "-silent",
            "-threads", "50",
            "-timeout", "10",
            "-retries", "2",
            "-title",
            "-tech-detect",
            "-status-code",
            "-content-length",
            "-content-type",
            "-follow-redirects",
            "-favicon",
            "-hash", "sha256",
            "-jarm",
            "-cdn",
            "-cname",
            "-asn",
            "-web-server",
            "-method",
            "-ip",
            "-response-time",
            "-location",
            "-tls-grab",
            "-pipeline",
            "-http2",
        ]
        return self.run_tool("httpx", args, timeout=900)

    def _run_httprobe(
        self,
        input_file: Path,
        output_file: Path,
    ) -> ToolResult:
        """Run httprobe for HTTP probing."""
        input_data = input_file.read_text()
        args = [
            "-c", "50",
            "-t", "10000",
            "-prefer-https",
        ]
        return self.run_tool(
            "httprobe",
            args,
            input_data=input_data,
            output_file=output_file,
            timeout=600,
        )

    def _parse_httpx_json(
        self,
        json_file: Path,
        status_dir: Path,
        result: ModuleResult,
    ) -> None:
        """Parse httpx JSON output for categorized insights."""
        if not json_file.exists():
            return

        technologies = {}
        status_codes = {}
        interesting_findings = []
        by_status = {}
        hosts_data = []
        cdn_hosts = []
        server_software = {}
        tls_info = []
        asn_info = {}
        http2_hosts = []
        cnames = {}

        try:
            for line in json_file.read_text().strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    url = data.get("url", "")
                    host = data.get("host", "")

                    hosts_data.append(data)

                    # Collect technologies
                    if "tech" in data:
                        for tech in data.get("tech", []):
                            technologies[tech] = technologies.get(tech, 0) + 1

                    # Collect status codes
                    status = data.get("status_code")
                    if status:
                        status_str = str(status)
                        status_codes[status_str] = status_codes.get(status_str, 0) + 1
                        if status_str not in by_status:
                            by_status[status_str] = []
                        by_status[status_str].append(url)

                    # Collect server software
                    server = data.get("webserver", "")
                    if server:
                        server_software[server] = server_software.get(server, 0) + 1

                    # CDN detection
                    if data.get("cdn"):
                        cdn_hosts.append({"url": url, "cdn": data.get("cdn_name", "unknown")})

                    # HTTP/2 detection
                    if data.get("http2"):
                        http2_hosts.append(url)

                    # ASN info
                    asn = data.get("asn", {})
                    if asn:
                        asn_name = asn.get("as_name", "")
                        if asn_name:
                            asn_info[asn_name] = asn_info.get(asn_name, 0) + 1

                    # CNAME records
                    cname = data.get("cname", "")
                    if cname:
                        cnames[host] = cname

                    # TLS info
                    tls = data.get("tls", {})
                    if tls:
                        tls_info.append({
                            "url": url,
                            "issuer": tls.get("issuer_organization", ""),
                            "subject": tls.get("subject_cn", ""),
                            "not_after": tls.get("not_after", ""),
                        })

                    # Flag interesting findings
                    title = data.get("title", "")

                    # Check for interesting titles
                    interesting_keywords = [
                        "admin", "login", "dashboard", "api", "dev",
                        "staging", "test", "internal", "jenkins", "gitlab",
                        "grafana", "kibana", "prometheus", "phpMyAdmin",
                        "swagger", "graphql", "console", "debug", "actuator",
                        "manager", "sonarqube", "nexus", "artifactory",
                        "rabbitmq", "elasticsearch", "mongo", "redis",
                    ]
                    if any(kw.lower() in title.lower() for kw in interesting_keywords):
                        interesting_findings.append({
                            "url": url,
                            "title": title,
                            "status": status,
                            "severity": "medium",
                            "reason": "interesting_title",
                        })

                    # Check for default pages
                    default_indicators = [
                        "welcome to nginx", "apache2 ubuntu", "it works",
                        "test page", "iis windows", "default page",
                        "congratulations", "under construction",
                    ]
                    if any(ind in title.lower() for ind in default_indicators):
                        interesting_findings.append({
                            "url": url,
                            "title": title,
                            "status": status,
                            "severity": "low",
                            "reason": "default_page",
                        })

                    # Check for error pages that reveal info
                    if status in [500, 502, 503] and title:
                        interesting_findings.append({
                            "url": url,
                            "title": title,
                            "status": status,
                            "severity": "low",
                            "reason": "error_page_with_info",
                        })

                    # Check for potential sensitive endpoints based on path
                    path_keywords = [
                        ".git", ".env", ".svn", "backup", "config", "db",
                        "dump", "export", "logs", "temp", "debug", "trace",
                    ]
                    if any(kw in url.lower() for kw in path_keywords):
                        interesting_findings.append({
                            "url": url,
                            "title": title,
                            "status": status,
                            "severity": "high",
                            "reason": "sensitive_path",
                        })

                except json.JSONDecodeError:
                    continue

            # Write status code files
            for status_code, urls in by_status.items():
                status_file = status_dir / f"{status_code}.txt"
                self.write_output_file(status_file, urls)
                result.output_files[f"status_{status_code}"] = status_file

            # Write technologies file
            if technologies:
                tech_file = self.output_path / "technologies.json"
                with open(tech_file, "w") as f:
                    json.dump({
                        "technologies": dict(sorted(technologies.items(), key=lambda x: x[1], reverse=True)),
                        "server_software": dict(sorted(server_software.items(), key=lambda x: x[1], reverse=True)),
                        "asn_distribution": dict(sorted(asn_info.items(), key=lambda x: x[1], reverse=True)),
                        "http2_support": len(http2_hosts),
                    }, f, indent=2)
                result.output_files["technologies"] = tech_file
                self.logger.info(f"  Detected {len(technologies)} unique technologies")

            # Write interesting hosts
            if interesting_findings:
                interesting_file = self.output_path / "interesting_hosts.txt"
                interesting_urls = list(set(f["url"] for f in interesting_findings))
                self.write_output_file(interesting_file, interesting_urls)
                result.output_files["interesting_hosts"] = interesting_file

                # Also write detailed JSON
                interesting_json = self.output_path / "interesting_hosts.json"
                with open(interesting_json, "w") as f:
                    json.dump(interesting_findings, f, indent=2)

                self.logger.info(f"  Found {len(interesting_findings)} interesting endpoints")

            # Write CDN hosts
            if cdn_hosts:
                cdn_file = self.output_path / "cdn_hosts.json"
                with open(cdn_file, "w") as f:
                    json.dump(cdn_hosts, f, indent=2)
                result.output_files["cdn_hosts"] = cdn_file
                result.stats["cdn_hosts"] = len(cdn_hosts)

            # Write TLS info
            if tls_info:
                tls_file = self.output_path / "tls_info.json"
                with open(tls_file, "w") as f:
                    json.dump(tls_info, f, indent=2)
                result.output_files["tls_info"] = tls_file
                result.stats["tls_hosts"] = len(tls_info)

            # Write HTTP/2 hosts
            if http2_hosts:
                http2_file = self.output_path / "http2_hosts.txt"
                self.write_output_file(http2_file, http2_hosts)
                result.output_files["http2_hosts"] = http2_file
                result.stats["http2_hosts"] = len(http2_hosts)

            # Write CNAMEs
            if cnames:
                cname_file = self.output_path / "cnames.json"
                with open(cname_file, "w") as f:
                    json.dump(cnames, f, indent=2)
                result.output_files["cnames"] = cname_file

            # Store in result
            result.metadata["technologies"] = technologies
            result.metadata["status_codes"] = status_codes
            result.metadata["server_software"] = server_software
            result.metadata["asn_info"] = asn_info
            result.findings.extend(interesting_findings[:50])

        except Exception as e:
            self.logger.error(f"Error parsing httpx JSON: {e}")

    def _save_json_summary(self, result: ModuleResult) -> None:
        """Save JSON summary."""
        summary = {
            "module": self.name,
            "stats": result.stats,
            "output_files": {k: str(v) for k, v in result.output_files.items()},
            "tools_used": list(self.available_tools),
            "technologies": result.metadata.get("technologies", {}),
            "status_codes": result.metadata.get("status_codes", {}),
            "server_software": result.metadata.get("server_software", {}),
            "findings_count": len(result.findings),
        }

        json_file = self.output_path / "http_probe_summary.json"
        with open(json_file, "w") as f:
            json.dump(summary, f, indent=2)

        result.output_files["json_summary"] = json_file
