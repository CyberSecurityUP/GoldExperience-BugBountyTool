"""
CORS Misconfiguration Detection Module

Checks for CORS misconfigurations:
- Reflected Origin
- Null Origin allowed
- Wildcard with credentials
- Subdomain bypass
- Pre-domain bypass (evil.com.target.com)
- Post-domain bypass (target.com.evil.com)

Output structure:
  cors_check/
    ├── vulnerable.txt
    ├── potential.txt
    ├── cors_details.json
    └── cors_summary.json
"""

import json
import time
import urllib.request
import urllib.parse
import ssl
from pathlib import Path
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import ActiveModule, ModuleResult


class CorsCheckModule(ActiveModule):
    """Check for CORS misconfigurations."""

    name = "cors_check"
    description = "Detect CORS misconfigurations that could lead to data theft"
    tools = []  # Pure Python implementation
    output_dir = "cors_check"

    # CORS test payloads
    CORS_TESTS = [
        {
            "name": "reflected_origin",
            "origin": "https://evil.com",
            "severity": "high",
            "description": "Origin is reflected in Access-Control-Allow-Origin",
        },
        {
            "name": "null_origin",
            "origin": "null",
            "severity": "high",
            "description": "Null origin is allowed",
        },
        {
            "name": "subdomain_bypass",
            "origin": "https://evil.{domain}",
            "severity": "medium",
            "description": "Subdomain of target is allowed (potential takeover)",
        },
        {
            "name": "pre_domain_bypass",
            "origin": "https://{domain}.evil.com",
            "severity": "high",
            "description": "Pre-domain bypass allowed",
        },
        {
            "name": "post_domain_bypass",
            "origin": "https://evil{domain}",
            "severity": "high",
            "description": "Post-domain bypass allowed",
        },
        {
            "name": "http_origin",
            "origin": "http://{domain}",
            "severity": "medium",
            "description": "HTTP origin allowed (downgrade attack)",
        },
    ]

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        **kwargs,
    ) -> ModuleResult:
        """
        Check targets for CORS misconfigurations.

        Args:
            targets: List of URLs to check
            resume: Skip if output exists
            input_file: File containing URLs

        Returns:
            ModuleResult with CORS findings
        """
        start_time = time.time()
        self.ensure_output_dir()

        result = ModuleResult(
            module_name=self.name,
            success=True,
            duration=0.0,
        )

        # Load targets
        if input_file and input_file.exists():
            targets = self.read_input_file(input_file)

        if not targets:
            self.logger.warning("No targets for CORS check")
            result.success = False
            result.duration = time.time() - start_time
            return result

        # Filter scope
        targets = self.filter_scope(targets)
        targets = list(set(targets))

        # Ensure URLs have protocol
        targets = [self._ensure_protocol(t) for t in targets]

        self.logger.info(f"{'='*50}")
        self.logger.info(f"Checking {len(targets)} targets for CORS issues")
        self.logger.info(f"{'='*50}")

        # Output files
        vulnerable_file = self.output_path / "vulnerable.txt"
        potential_file = self.output_path / "potential.txt"
        details_file = self.output_path / "cors_details.json"

        if resume and vulnerable_file.exists():
            self.logger.info("Resuming: Using existing CORS results")
            vulns = self.read_input_file(vulnerable_file)
            result.stats["vulnerable_count"] = len(vulns)
            result.duration = time.time() - start_time
            return result

        vulnerable = []
        potential = []
        all_findings = []

        # Check each target
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self._check_cors, url): url
                for url in targets
            }

            for future in as_completed(futures):
                url = futures[future]
                try:
                    findings = future.result()
                    if findings:
                        all_findings.extend(findings)
                        for finding in findings:
                            if finding["severity"] == "high":
                                vulnerable.append(url)
                                result.findings.append(finding)
                            else:
                                potential.append(url)
                except Exception as e:
                    self.logger.debug(f"Error checking {url}: {e}")

        # Deduplicate
        vulnerable = list(set(vulnerable))
        potential = list(set(potential))

        # Write results
        if vulnerable:
            self.write_output_file(vulnerable_file, vulnerable)
            result.output_files["vulnerable"] = vulnerable_file
            result.stats["vulnerable_count"] = len(vulnerable)
            self.logger.info(f"VULNERABLE: {len(vulnerable)} targets with CORS issues")

        if potential:
            self.write_output_file(potential_file, potential)
            result.output_files["potential"] = potential_file
            result.stats["potential_count"] = len(potential)

        if all_findings:
            with open(details_file, "w") as f:
                json.dump(all_findings, f, indent=2)
            result.output_files["details"] = details_file

        # Save summary
        self._save_json_summary(result)

        result.duration = time.time() - start_time
        return result

    def _ensure_protocol(self, url: str) -> str:
        """Ensure URL has protocol."""
        if not url.startswith(("http://", "https://")):
            return f"https://{url}"
        return url

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.split(":")[0]

    def _check_cors(self, url: str) -> List[Dict[str, Any]]:
        """Check a URL for CORS misconfigurations."""
        findings = []
        domain = self._extract_domain(url)

        # SSL context
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for test in self.CORS_TESTS:
            origin = test["origin"].replace("{domain}", domain)

            try:
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Origin": origin,
                        "Accept": "*/*",
                    },
                    method="GET"
                )

                with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                    headers = dict(response.headers)
                    acao = headers.get("Access-Control-Allow-Origin", "")
                    acac = headers.get("Access-Control-Allow-Credentials", "")

                    # Check for vulnerabilities
                    is_vulnerable = False
                    vuln_details = {}

                    if test["name"] == "reflected_origin":
                        if acao == origin:
                            is_vulnerable = True
                            vuln_details["type"] = "reflected"

                    elif test["name"] == "null_origin":
                        if acao == "null":
                            is_vulnerable = True
                            vuln_details["type"] = "null_allowed"

                    elif acao == origin:
                        # Other bypass tests
                        is_vulnerable = True
                        vuln_details["type"] = test["name"]

                    # Check for wildcard with credentials
                    if acao == "*" and acac.lower() == "true":
                        is_vulnerable = True
                        vuln_details["type"] = "wildcard_with_credentials"

                    if is_vulnerable:
                        finding = {
                            "url": url,
                            "test": test["name"],
                            "origin_sent": origin,
                            "acao": acao,
                            "acac": acac,
                            "severity": test["severity"],
                            "description": test["description"],
                            **vuln_details,
                        }
                        findings.append(finding)
                        self.logger.info(f"  CORS issue: {url} - {test['name']}")

            except Exception as e:
                self.logger.debug(f"Error testing {test['name']} on {url}: {e}")
                continue

        return findings

    def _save_json_summary(self, result: ModuleResult) -> None:
        """Save JSON summary."""
        summary = {
            "module": self.name,
            "stats": result.stats,
            "output_files": {k: str(v) for k, v in result.output_files.items()},
            "tests_performed": [t["name"] for t in self.CORS_TESTS],
            "findings_count": len(result.findings),
        }

        json_file = self.output_path / "cors_summary.json"
        with open(json_file, "w") as f:
            json.dump(summary, f, indent=2)

        result.output_files["json_summary"] = json_file
