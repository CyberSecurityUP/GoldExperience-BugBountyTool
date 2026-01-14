"""
Vulnerability Scanning Module - Enhanced Version

Automated vulnerability scanning with categorized output:
- nuclei (primary with CVE-specific templates)
- jaeles (secondary)
- Targeted CVE scans for high-impact vulnerabilities

Output structure:
  nuclei/
    ├── raw/
    │   ├── nuclei.txt
    │   ├── nuclei.jsonl
    │   ├── cve_scan.jsonl
    │   └── jaeles/
    ├── by_severity/
    │   ├── critical.txt
    │   ├── high.txt
    │   ├── medium.txt
    │   ├── low.txt
    │   └── info.txt
    ├── by_type/
    │   ├── cve.txt
    │   ├── misconfig.txt
    │   ├── exposure.txt
    │   └── takeover.txt
    ├── all_findings.txt
    ├── prioritized.txt (critical + high)
    ├── cve_findings.txt
    └── nuclei_scan_summary.json
"""

import json
import time
from pathlib import Path
from typing import List, Optional, Dict, Any
from collections import defaultdict

from .base import ActiveModule, ModuleResult
from ..utils.process import ToolResult, check_tool_exists
from ..utils.dedup import deduplicate_lines


class VulnScanModule(ActiveModule):
    """Enhanced vulnerability scanning with categorized output."""

    name = "nuclei_scan"
    description = "Scan for known vulnerabilities using template-based scanners"
    tools = ["nuclei", "jaeles"]
    output_dir = "nuclei"

    # Template categories for classification
    TEMPLATE_CATEGORIES = {
        "cve": ["cve-", "CVE-"],
        "misconfig": ["misconfig", "misconfiguration", "default-", "exposed-"],
        "exposure": ["exposure", "disclosure", "leak", "sensitive"],
        "takeover": ["takeover", "subdomain-takeover"],
        "injection": ["sqli", "xss", "ssti", "injection", "rce", "lfi", "rfi"],
        "auth": ["auth-bypass", "default-login", "weak-password", "brute"],
    }

    # High-impact CVEs to specifically scan for (grouped by technology)
    HIGH_IMPACT_CVES = {
        "general": [
            "cves/2021/CVE-2021-44228",   # Log4Shell
            "cves/2021/CVE-2021-45046",   # Log4j
            "cves/2022/CVE-2022-22965",   # Spring4Shell
            "cves/2023/CVE-2023-44487",   # HTTP/2 Rapid Reset
            "cves/2024/CVE-2024-3400",    # Palo Alto PAN-OS
        ],
        "apache": [
            "cves/2021/CVE-2021-41773",   # Apache Path Traversal
            "cves/2021/CVE-2021-42013",   # Apache Path Traversal
            "cves/2019/CVE-2019-0211",    # Apache Privilege Escalation
            "cves/2023/CVE-2023-25690",   # Apache HTTP Request Smuggling
        ],
        "confluence": [
            "cves/2022/CVE-2022-26134",   # Confluence OGNL Injection RCE
            "cves/2023/CVE-2023-22515",   # Confluence Broken Access Control
            "cves/2023/CVE-2023-22518",   # Confluence Auth Bypass
        ],
        "gitlab": [
            "cves/2021/CVE-2021-22205",   # GitLab RCE
            "cves/2023/CVE-2023-2825",    # GitLab Path Traversal
        ],
        "jenkins": [
            "cves/2019/CVE-2019-1003000", # Jenkins RCE
            "cves/2024/CVE-2024-23897",   # Jenkins Arbitrary File Read
        ],
        "vmware": [
            "cves/2021/CVE-2021-21985",   # vSphere RCE
            "cves/2022/CVE-2022-22954",   # Workspace ONE RCE
        ],
        "citrix": [
            "cves/2019/CVE-2019-19781",   # Citrix ADC RCE
            "cves/2023/CVE-2023-3519",    # Citrix NetScaler RCE
        ],
        "fortinet": [
            "cves/2022/CVE-2022-40684",   # FortiOS Auth Bypass
            "cves/2023/CVE-2023-27997",   # FortiOS Heap Overflow
        ],
        "exchange": [
            "cves/2021/CVE-2021-26855",   # ProxyLogon
            "cves/2021/CVE-2021-34473",   # ProxyShell
            "cves/2022/CVE-2022-41040",   # ProxyNotShell
        ],
        "ivanti": [
            "cves/2024/CVE-2024-21887",   # Ivanti Connect Secure RCE
            "cves/2023/CVE-2023-46805",   # Ivanti Auth Bypass
        ],
        "wordpress": [
            "cves/2022/CVE-2022-21661",   # WP Core SQLi
        ],
        "f5": [
            "cves/2020/CVE-2020-5902",    # F5 BIG-IP RCE
            "cves/2022/CVE-2022-1388",    # F5 BIG-IP Auth Bypass
        ],
    }

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        severity: str = "low,medium,high,critical",
        templates: Optional[List[str]] = None,
        rate_limit: int = 150,
        **kwargs,
    ) -> ModuleResult:
        """
        Run vulnerability scanning on targets.

        Args:
            targets: List of URLs to scan
            resume: Skip if output exists
            input_file: File containing URLs
            severity: Severity levels to scan
            templates: Specific templates to use
            rate_limit: Requests per second

        Returns:
            ModuleResult with categorized vulnerabilities
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
        severity_dir = self.output_path / "by_severity"
        severity_dir.mkdir(parents=True, exist_ok=True)
        type_dir = self.output_path / "by_type"
        type_dir.mkdir(parents=True, exist_ok=True)

        # Load targets
        if input_file and input_file.exists():
            targets = self.read_input_file(input_file)

        if not targets:
            self.logger.warning("No targets provided for vulnerability scanning")
            result.duration = time.time() - start_time
            return result

        # Filter and deduplicate
        targets = self.filter_scope(targets)
        targets = list(set(targets))

        self.logger.info(f"{'='*50}")
        self.logger.info(f"Scanning {len(targets)} targets for vulnerabilities")
        self.logger.info(f"{'='*50}")

        # Write targets
        targets_file = self.output_path / "targets.txt"
        self.write_output_file(targets_file, targets)

        # Output files
        all_findings_file = self.output_path / "all_findings.txt"

        if resume and all_findings_file.exists() and all_findings_file.stat().st_size > 0:
            self.logger.info("Resuming: Using existing vulnerability scan results")
            result.duration = time.time() - start_time
            return result

        # Run nuclei
        if check_tool_exists("nuclei"):
            nuclei_output = raw_dir / "nuclei.txt"
            nuclei_json = raw_dir / "nuclei.jsonl"

            nuclei_result = self._run_nuclei(
                targets_file,
                nuclei_output,
                nuclei_json,
                severity,
                templates,
                rate_limit,
            )
            result.add_tool_result(nuclei_result)

            if nuclei_result.success:
                result.output_files["nuclei_raw"] = nuclei_output
                result.output_files["nuclei_json"] = nuclei_json

                # Parse and categorize findings
                self._parse_and_categorize_nuclei(
                    nuclei_json, severity_dir, type_dir, all_findings_file, result
                )

        # Run targeted CVE scan
        if check_tool_exists("nuclei"):
            cve_json = raw_dir / "cve_scan.jsonl"
            cve_result = self._run_cve_scan(targets_file, cve_json, rate_limit)
            result.add_tool_result(cve_result)

            if cve_result.success and cve_json.exists():
                result.output_files["cve_scan"] = cve_json
                cve_count = sum(1 for _ in open(cve_json)) if cve_json.stat().st_size > 0 else 0
                result.stats["cve_scan_count"] = cve_count
                if cve_count > 0:
                    self.logger.warning(f"  CVE Scan: {cve_count} HIGH-IMPACT CVEs detected!")

        # Run jaeles as supplement
        if check_tool_exists("jaeles"):
            jaeles_dir = raw_dir / "jaeles"
            jaeles_dir.mkdir(exist_ok=True)
            jaeles_output = jaeles_dir / "findings.txt"

            jaeles_result = self._run_jaeles(targets_file, jaeles_output)
            result.add_tool_result(jaeles_result)

            if jaeles_result.success and jaeles_output.exists():
                result.output_files["jaeles"] = jaeles_output
                count = len(self.read_input_file(jaeles_output))
                result.stats["jaeles_count"] = count
                self.logger.info(f"  jaeles: {count} findings")

        # Save JSON summary
        self._save_json_summary(result)

        result.duration = time.time() - start_time
        return result

    def _run_nuclei(
        self,
        input_file: Path,
        output_file: Path,
        json_file: Path,
        severity: str,
        templates: Optional[List[str]],
        rate_limit: int,
    ) -> ToolResult:
        """Run nuclei vulnerability scanner."""
        args = [
            "-l", str(input_file),
            "-o", str(output_file),
            "-jsonl",
            "-output", str(json_file),
            "-severity", severity,
            "-rate-limit", str(rate_limit),
            "-bulk-size", "25",
            "-concurrency", "25",
            "-silent",
            "-nc",  # No color
            "-stats",
            "-retries", "2",
        ]

        if templates:
            for t in templates:
                args.extend(["-t", t])
        else:
            # Use default templates with automatic updates
            args.extend(["-automatic-scan"])

        return self.run_tool("nuclei", args, timeout=3600)  # 1 hour timeout

    def _run_cve_scan(
        self,
        input_file: Path,
        json_file: Path,
        rate_limit: int,
    ) -> ToolResult:
        """Run nuclei with targeted high-impact CVE templates."""
        self.logger.info("Running targeted CVE scan for high-impact vulnerabilities...")

        # Collect all CVE templates
        all_templates = []
        for category, templates in self.HIGH_IMPACT_CVES.items():
            all_templates.extend(templates)

        # Build args with multiple -t flags for each template
        args = [
            "-l", str(input_file),
            "-jsonl",
            "-o", str(json_file),
            "-severity", "critical,high",
            "-rate-limit", str(rate_limit),
            "-bulk-size", "15",
            "-concurrency", "15",
            "-silent",
            "-nc",
            "-retries", "2",
            "-timeout", "15",
        ]

        # Add each CVE template
        for template in all_templates:
            args.extend(["-t", template])

        return self.run_tool("nuclei", args, timeout=1800)  # 30 min timeout

    def _run_jaeles(self, input_file: Path, output_file: Path) -> ToolResult:
        """Run jaeles vulnerability scanner."""
        jaeles_out_dir = output_file.parent / "jaeles_out"
        jaeles_out_dir.mkdir(exist_ok=True)

        args = [
            "scan",
            "-U", str(input_file),
            "-o", str(jaeles_out_dir),
            "-c", "20",
            "--no-db",
            "-q",  # Quiet mode
        ]

        result = self.run_tool("jaeles", args, timeout=1800)

        # Merge jaeles output files
        if result.success and jaeles_out_dir.exists():
            all_findings = []
            for f in jaeles_out_dir.glob("*.txt"):
                all_findings.extend(f.read_text().strip().split("\n"))
            if all_findings:
                output_file.write_text("\n".join(all_findings))
                result.result_count = len(all_findings)

        return result

    def _parse_and_categorize_nuclei(
        self,
        json_file: Path,
        severity_dir: Path,
        type_dir: Path,
        all_findings_file: Path,
        result: ModuleResult,
    ) -> None:
        """Parse nuclei JSON output and categorize findings."""
        if not json_file.exists():
            return

        # Data structures for categorization
        by_severity: Dict[str, List[Dict]] = defaultdict(list)
        by_type: Dict[str, List[Dict]] = defaultdict(list)
        all_vulns: List[Dict] = []

        try:
            for line in json_file.read_text().strip().split("\n"):
                if not line:
                    continue

                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    severity = info.get("severity", "info").lower()
                    template_id = data.get("template-id", "unknown")
                    matched_at = data.get("matched-at", "")
                    name = info.get("name", "")
                    description = info.get("description", "")
                    tags = info.get("tags", [])

                    vuln = {
                        "template": template_id,
                        "name": name,
                        "severity": severity,
                        "url": matched_at,
                        "description": description[:500] if description else "",
                        "tags": tags,
                        "host": data.get("host", ""),
                        "matched": data.get("matcher-name", ""),
                    }

                    all_vulns.append(vuln)

                    # Categorize by severity
                    by_severity[severity].append(vuln)

                    # Categorize by type
                    template_lower = template_id.lower()
                    categorized = False
                    for category, patterns in self.TEMPLATE_CATEGORIES.items():
                        if any(p.lower() in template_lower for p in patterns):
                            by_type[category].append(vuln)
                            categorized = True
                            break

                    if not categorized:
                        by_type["other"].append(vuln)

                    # Add to findings for high-priority items
                    if severity in ["critical", "high"]:
                        result.findings.append({
                            "type": "vulnerability",
                            "template": template_id,
                            "name": name,
                            "severity": severity,
                            "url": matched_at,
                        })

                except json.JSONDecodeError:
                    continue

            # Write severity-based files
            for sev, vulns in by_severity.items():
                if vulns:
                    sev_file = severity_dir / f"{sev}.txt"
                    lines = [f"{v['template']}: {v['url']}" for v in vulns]
                    self.write_output_file(sev_file, deduplicate_lines(lines))
                    result.output_files[f"severity_{sev}"] = sev_file
                    result.stats[f"{sev}_count"] = len(vulns)

            # Write type-based files
            for cat, vulns in by_type.items():
                if vulns:
                    type_file = type_dir / f"{cat}.txt"
                    lines = [f"{v['template']}: {v['url']}" for v in vulns]
                    self.write_output_file(type_file, deduplicate_lines(lines))
                    result.output_files[f"type_{cat}"] = type_file
                    result.stats[f"type_{cat}_count"] = len(vulns)

            # Write all findings
            if all_vulns:
                all_lines = [f"[{v['severity'].upper()}] {v['template']}: {v['url']}" for v in all_vulns]
                self.write_output_file(all_findings_file, deduplicate_lines(all_lines))
                result.output_files["all_findings"] = all_findings_file
                result.stats["total_findings"] = len(all_vulns)

            # Write prioritized file (critical + high)
            prioritized = by_severity.get("critical", []) + by_severity.get("high", [])
            if prioritized:
                prioritized_file = self.output_path / "prioritized.txt"
                lines = [f"[{v['severity'].upper()}] {v['name']}: {v['url']}" for v in prioritized]
                self.write_output_file(prioritized_file, deduplicate_lines(lines))
                result.output_files["prioritized"] = prioritized_file

            # Write detailed JSON with all vulnerability data
            vuln_json_file = self.output_path / "vulnerabilities.json"
            with open(vuln_json_file, "w") as f:
                json.dump({
                    "by_severity": {k: v for k, v in by_severity.items()},
                    "by_type": {k: v for k, v in by_type.items()},
                    "total": len(all_vulns),
                    "summary": {
                        "critical": len(by_severity.get("critical", [])),
                        "high": len(by_severity.get("high", [])),
                        "medium": len(by_severity.get("medium", [])),
                        "low": len(by_severity.get("low", [])),
                        "info": len(by_severity.get("info", [])),
                    }
                }, f, indent=2)
            result.output_files["vulnerabilities_json"] = vuln_json_file

            # Log summary
            total = len(all_vulns)
            critical = len(by_severity.get("critical", []))
            high = len(by_severity.get("high", []))

            self.logger.info(f"Total findings: {total}")
            if critical > 0 or high > 0:
                self.logger.warning(
                    f"PRIORITY: {critical} CRITICAL, {high} HIGH vulnerabilities!"
                )
            self.logger.info(f"  Critical: {critical}")
            self.logger.info(f"  High: {high}")
            self.logger.info(f"  Medium: {len(by_severity.get('medium', []))}")
            self.logger.info(f"  Low: {len(by_severity.get('low', []))}")
            self.logger.info(f"  Info: {len(by_severity.get('info', []))}")

            result.metadata["vulnerability_summary"] = {
                "critical": critical,
                "high": high,
                "medium": len(by_severity.get("medium", [])),
                "low": len(by_severity.get("low", [])),
                "info": len(by_severity.get("info", [])),
                "total": total,
            }

        except Exception as e:
            self.logger.error(f"Error parsing nuclei output: {e}")

    def _save_json_summary(self, result: ModuleResult) -> None:
        """Save JSON summary."""
        summary = {
            "module": self.name,
            "stats": result.stats,
            "output_files": {k: str(v) for k, v in result.output_files.items()},
            "tools_used": list(self.available_tools),
            "vulnerability_summary": result.metadata.get("vulnerability_summary", {}),
            "high_priority_count": result.stats.get("critical_count", 0) + result.stats.get("high_count", 0),
            "findings_count": len(result.findings),
        }

        json_file = self.output_path / "nuclei_scan_summary.json"
        with open(json_file, "w") as f:
            json.dump(summary, f, indent=2)

        result.output_files["json_summary"] = json_file
