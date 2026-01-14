"""
OSINT Module

Open Source Intelligence gathering:
- shodan
- censys
- metabigor
"""

import json
import os
import time
from pathlib import Path
from typing import List, Optional

from .base import PassiveModule, ModuleResult
from ..utils.normalize import normalize_domain


class OsintModule(PassiveModule):
    """Open Source Intelligence gathering from various sources."""

    name = "osint"
    description = "Gather intelligence from Shodan, Censys, and other OSINT sources"
    tools = ["shodan", "censys", "metabigor"]
    output_dir = "osint"

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        shodan_api_key: Optional[str] = None,
        censys_api_id: Optional[str] = None,
        censys_api_secret: Optional[str] = None,
        **kwargs,
    ) -> ModuleResult:
        """
        Run OSINT gathering.

        Args:
            targets: List of domains/IPs to research
            resume: Skip if output exists
            shodan_api_key: Shodan API key
            censys_api_id: Censys API ID
            censys_api_secret: Censys API secret

        Returns:
            ModuleResult with OSINT data
        """
        start_time = time.time()
        self.ensure_output_dir()

        result = ModuleResult(
            module_name=self.name,
            success=True,
            duration=0.0,
        )

        if not targets:
            self.logger.warning("No targets for OSINT gathering")
            result.duration = time.time() - start_time
            return result

        # Get API keys from params or environment
        shodan_key = shodan_api_key or os.environ.get("SHODAN_API_KEY")
        censys_id = censys_api_id or os.environ.get("CENSYS_API_ID")
        censys_secret = censys_api_secret or os.environ.get("CENSYS_API_SECRET")

        self.logger.info(f"Running OSINT on {len(targets)} targets")

        # Output files
        shodan_output = self.get_output_file("shodan.json")
        metabigor_output = self.get_output_file("metabigor.txt")

        if resume and self.check_resume(shodan_output):
            result.duration = time.time() - start_time
            return result

        # Run Shodan
        if "shodan" in self.available_tools and shodan_key:
            for target in targets[:10]:
                domain = normalize_domain(target)
                if domain:
                    sh_out = self.get_output_file(f"shodan_{domain}.json")
                    sh_result = self._run_shodan(domain, sh_out, shodan_key)
                    result.add_tool_result(sh_result)
                    if sh_result.success and sh_out.exists():
                        self._parse_shodan(sh_out, result)

        # Run metabigor (doesn't require API key)
        if "metabigor" in self.available_tools:
            for target in targets[:10]:
                domain = normalize_domain(target)
                if domain:
                    mb_out = self.get_output_file(f"metabigor_{domain}.txt")
                    mb_result = self._run_metabigor(domain, mb_out)
                    result.add_tool_result(mb_result)
                    if mb_result.success and mb_out.exists():
                        result.output_files[f"metabigor_{domain}"] = mb_out

        result.duration = time.time() - start_time
        return result

    def _run_shodan(self, target: str, output_file: Path, api_key: str):
        """Run Shodan search."""
        # Set API key in environment
        env = {"SHODAN_API_KEY": api_key}

        args = [
            "search",
            "--fields", "ip_str,port,org,hostnames,os,product",
            "-O", str(output_file),
            f"hostname:{target}",
        ]
        return self.run_tool("shodan", args, timeout=120)

    def _run_metabigor(self, target: str, output_file: Path):
        """Run metabigor for OSINT."""
        args = [
            "net",
            "-t", target,
            "-o", str(output_file),
        ]
        return self.run_tool("metabigor", args, timeout=120)

    def _parse_shodan(self, output_file: Path, result: ModuleResult) -> None:
        """Parse Shodan results for interesting data."""
        if not output_file.exists():
            return

        try:
            data = json.loads(output_file.read_text())
            matches = data.get("matches", [])

            ports = set()
            products = set()
            orgs = set()
            vulnerabilities = []

            for match in matches:
                if "port" in match:
                    ports.add(match["port"])
                if "product" in match:
                    products.add(match["product"])
                if "org" in match:
                    orgs.add(match["org"])
                if "vulns" in match:
                    for vuln in match["vulns"]:
                        vulnerabilities.append({
                            "cve": vuln,
                            "ip": match.get("ip_str", ""),
                            "port": match.get("port", ""),
                        })

            result.metadata["shodan"] = {
                "total_results": len(matches),
                "unique_ports": list(ports),
                "products": list(products),
                "organizations": list(orgs),
            }

            if vulnerabilities:
                result.stats["shodan_vulns"] = len(vulnerabilities)
                for vuln in vulnerabilities[:10]:
                    result.findings.append({
                        "type": "shodan_vulnerability",
                        "cve": vuln["cve"],
                        "ip": vuln["ip"],
                        "port": vuln["port"],
                        "severity": "high",
                    })

                self.logger.warning(
                    f"Shodan found {len(vulnerabilities)} potential vulnerabilities!"
                )

        except Exception as e:
            self.logger.error(f"Error parsing Shodan output: {e}")
