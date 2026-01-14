"""
Subdomain Takeover Module

Checks for potential subdomain takeover vulnerabilities:
- subjack
- nuclei (with takeover templates)
- can-i-take-over-xyz fingerprints

Output structure:
  subdomain_takeover/
    ├── raw/
    │   ├── subjack.txt
    │   └── nuclei_takeover.txt
    ├── vulnerable.txt (confirmed takeovers)
    ├── potential.txt (possible takeovers)
    └── takeover_summary.json
"""

import json
import time
from pathlib import Path
from typing import List, Optional, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import ActiveModule, ModuleResult
from ..utils.process import ToolResult, check_tool_exists
from ..utils.dedup import deduplicate_lines


class SubdomainTakeoverModule(ActiveModule):
    """Check for subdomain takeover vulnerabilities."""

    name = "subdomain_takeover"
    description = "Detect potential subdomain takeover vulnerabilities"
    tools = ["subjack", "nuclei"]
    output_dir = "subdomain_takeover"

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        **kwargs,
    ) -> ModuleResult:
        """
        Check for subdomain takeover vulnerabilities.

        Args:
            targets: List of subdomains to check
            resume: Skip if output exists
            input_file: File containing subdomains (usually from subdomain_enum)

        Returns:
            ModuleResult with takeover findings
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

        # Load targets from file if provided
        if input_file and input_file.exists():
            targets = self.read_input_file(input_file)

        if not targets:
            self.logger.warning("No targets for subdomain takeover check")
            result.success = False
            result.duration = time.time() - start_time
            return result

        # Filter scope and deduplicate
        targets = self.filter_scope(targets)
        targets = list(set(targets))

        self.logger.info(f"{'='*50}")
        self.logger.info(f"Checking {len(targets)} subdomains for takeover")
        self.logger.info(f"{'='*50}")

        # Write targets file
        targets_file = self.output_path / "targets.txt"
        self.write_output_file(targets_file, targets)

        # Output files
        vulnerable_file = self.output_path / "vulnerable.txt"
        potential_file = self.output_path / "potential.txt"

        if resume and vulnerable_file.exists():
            self.logger.info("Resuming: Using existing takeover results")
            vulns = self.read_input_file(vulnerable_file)
            result.stats["vulnerable_count"] = len(vulns)
            result.duration = time.time() - start_time
            return result

        vulnerable = []
        potential = []

        # Run subjack
        if check_tool_exists("subjack"):
            subjack_out = raw_dir / "subjack.txt"
            subjack_result = self._run_subjack(targets_file, subjack_out)
            result.add_tool_result(subjack_result)

            if subjack_result.success and subjack_out.exists():
                subjack_findings = self._parse_subjack(subjack_out)
                vulnerable.extend(subjack_findings.get("vulnerable", []))
                potential.extend(subjack_findings.get("potential", []))
                self.logger.info(f"  subjack: {len(subjack_findings.get('vulnerable', []))} vulnerable")

        # Run nuclei with takeover templates
        if check_tool_exists("nuclei"):
            nuclei_out = raw_dir / "nuclei_takeover.txt"
            nuclei_result = self._run_nuclei_takeover(targets_file, nuclei_out)
            result.add_tool_result(nuclei_result)

            if nuclei_result.success and nuclei_out.exists():
                nuclei_findings = self._parse_nuclei_takeover(nuclei_out)
                vulnerable.extend(nuclei_findings)
                self.logger.info(f"  nuclei takeover: {len(nuclei_findings)} vulnerable")

        # Deduplicate and write results
        vulnerable = list(set(vulnerable))
        potential = list(set(potential))

        if vulnerable:
            self.write_output_file(vulnerable_file, vulnerable)
            result.output_files["vulnerable"] = vulnerable_file
            result.stats["vulnerable_count"] = len(vulnerable)
            self.logger.info(f"VULNERABLE: {len(vulnerable)} subdomains")

            # Add findings for high-risk items
            for vuln in vulnerable:
                result.findings.append({
                    "type": "subdomain_takeover",
                    "severity": "high",
                    "subdomain": vuln,
                    "source": "subdomain_takeover",
                })

        if potential:
            self.write_output_file(potential_file, potential)
            result.output_files["potential"] = potential_file
            result.stats["potential_count"] = len(potential)
            self.logger.info(f"Potential: {len(potential)} subdomains")

        # Save JSON summary
        self._save_json_summary(result, vulnerable, potential)

        result.duration = time.time() - start_time
        return result

    def _run_subjack(self, input_file: Path, output_file: Path) -> ToolResult:
        """Run subjack for subdomain takeover detection."""
        args = [
            "-w", str(input_file),
            "-o", str(output_file),
            "-ssl",
            "-t", "50",
            "-timeout", "30",
            "-a",  # All results, including potential
        ]
        return self.run_tool("subjack", args, timeout=600)

    def _run_nuclei_takeover(self, input_file: Path, output_file: Path) -> ToolResult:
        """Run nuclei with takeover templates."""
        args = [
            "-l", str(input_file),
            "-o", str(output_file),
            "-t", "takeovers/",
            "-silent",
            "-c", "50",
            "-timeout", "10",
            "-retries", "2",
        ]
        return self.run_tool("nuclei", args, timeout=900)

    def _parse_subjack(self, output_file: Path) -> Dict[str, List[str]]:
        """Parse subjack output."""
        findings = {"vulnerable": [], "potential": []}

        try:
            content = output_file.read_text().strip()
            if not content:
                return findings

            for line in content.split("\n"):
                line = line.strip()
                if not line:
                    continue

                # subjack format: [Vulnerable] subdomain.example.com
                # or [Not Vulnerable] subdomain.example.com
                if "[Vulnerable]" in line or "[vulnerable]" in line.lower():
                    subdomain = line.split("]")[-1].strip()
                    if subdomain:
                        findings["vulnerable"].append(subdomain)
                elif "[Edge Case]" in line or "potential" in line.lower():
                    subdomain = line.split("]")[-1].strip()
                    if subdomain:
                        findings["potential"].append(subdomain)
                elif line.startswith("http"):
                    # Some versions output just URLs
                    findings["potential"].append(line)

        except Exception as e:
            self.logger.error(f"Error parsing subjack output: {e}")

        return findings

    def _parse_nuclei_takeover(self, output_file: Path) -> List[str]:
        """Parse nuclei takeover output."""
        findings = []

        try:
            content = output_file.read_text().strip()
            if not content:
                return findings

            for line in content.split("\n"):
                line = line.strip()
                if not line:
                    continue

                # nuclei format: [template-id] [protocol] [severity] URL
                # Extract the URL/subdomain
                parts = line.split()
                if parts:
                    url = parts[-1]  # URL is usually last
                    if url.startswith("http"):
                        findings.append(url)
                    elif "." in url:  # Might be just subdomain
                        findings.append(url)

        except Exception as e:
            self.logger.error(f"Error parsing nuclei takeover output: {e}")

        return findings

    def _save_json_summary(
        self,
        result: ModuleResult,
        vulnerable: List[str],
        potential: List[str],
    ) -> None:
        """Save JSON summary."""
        summary = {
            "module": self.name,
            "stats": result.stats,
            "output_files": {k: str(v) for k, v in result.output_files.items()},
            "tools_used": list(self.available_tools),
            "vulnerable_subdomains": vulnerable,
            "potential_subdomains": potential[:50],  # Limit for readability
        }

        json_file = self.output_path / "takeover_summary.json"
        with open(json_file, "w") as f:
            json.dump(summary, f, indent=2)

        result.output_files["json_summary"] = json_file
